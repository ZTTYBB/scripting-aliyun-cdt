import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { createRequire } from "node:module"
import { fileURLToPath } from "node:url"
import test from "node:test"
import vm from "node:vm"

const require = createRequire(import.meta.url)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")

function cachedEsbuild() {
  try {
    return require("esbuild")
  } catch {}
  const roots = new Set([
    process.env.npm_config_cache,
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "npm-cache"),
    join(homedir(), "AppData", "Local", "npm-cache"),
    join(homedir(), ".npm")
  ].filter(Boolean))
  for (const root of roots) {
    const cache = join(root, "_npx")
    if (!existsSync(cache)) continue
    for (const entry of readdirSync(cache, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue
      const path = join(cache, entry.name, "node_modules", "esbuild")
      const metadata = join(path, "package.json")
      if (existsSync(metadata) && JSON.parse(readFileSync(metadata, "utf8")).version === "0.25.0") {
        return require(path)
      }
    }
  }
  throw new Error("Install esbuild@0.25.0 or reuse the existing npx cache before running the tests.")
}

const esbuild = cachedEsbuild()
const runtimeCode = esbuild.transformSync(readFileSync(join(projectRoot, "monitor_runtime.ts"), "utf8"), {
  loader: "ts",
  format: "cjs",
  target: "es2020"
}).code
const widgetSource = readFileSync(join(projectRoot, "widget.tsx"), "utf8")
const widgetCode = esbuild.buildSync({
  stdin: {
    contents: widgetSource.replace(/\bmain\(\)\s*$/, "export { main, fetchWidgetData, adaptDashboardSnapshotForWidget }"),
    loader: "tsx",
    resolveDir: projectRoot,
    sourcefile: "widget.tsx"
  },
  bundle: true,
  write: false,
  format: "cjs",
  target: "es2020",
  external: ["scripting"],
  jsxFactory: "__jsx",
  jsxFragment: "__fragment"
}).outputFiles[0].text

const config = {
  accessKeyId: "offline-account-a",
  accessKeySecret: "offline-secret-a",
  regionId: "cn-hongkong",
  ecsInstanceId: "i-offline-a",
  trafficThresholdGB: 200,
  vpsCutoffReferenceGB: 195,
  resetDayOfMonth: 1
}
const configKey = "aliyun_cdt_monitor_config"
const widgetKey = "aliyun_cdt_widget_cache"
const dashboardKey = "aliyun_cdt_dashboard_cache"
const dateAt = (month, day, hour = 12) => new Date(2026, month - 1, day, hour)

function harness({
  storage = new Map(),
  clock = { now: dateAt(10, 12).getTime() },
  fetch,
  family = "accessoryInline",
  noAbortController = false,
  timeoutCap
} = {}) {
  class ClockDate extends Date {
    constructor(...args) {
      super(...(args.length ? args : [clock.now]))
    }
    static now() {
      return clock.now
    }
  }
  const presented = []
  const scripting = new Proxy({
    Widget: {
      family,
      displaySize: { width: 329, height: 155 },
      present(view, options) {
        presented.push({ view, options })
      }
    }
  }, {
    get(target, property) {
      return property in target ? target[property] : String(property)
    }
  })
  const context = {
    Date: ClockDate,
    Storage: { get: key => storage.get(key), set: (key, value) => storage.set(key, value) },
    setTimeout: timeoutCap
      ? (callback, delay) => setTimeout(callback, Math.min(delay, timeoutCap))
      : setTimeout,
    clearTimeout,
    ...(noAbortController ? {} : { AbortController }),
    console: { log() {}, warn() {}, error() {} },
    fetch: fetch ?? (() => Promise.reject(new Error("offline"))),
    __jsx(type, props, ...children) {
      const flattened = children.flat(Infinity).filter(value => value !== undefined && value !== null && value !== false)
      return typeof type === "function"
        ? type({ ...props, children: flattened.length === 1 ? flattened[0] : flattened })
        : { type, props: props ?? {}, children: flattened }
    },
    __fragment: "Fragment",
    require(name) {
      assert.equal(name, "scripting")
      return scripting
    }
  }
  function load(code, filename) {
    const module = { exports: {} }
    vm.runInNewContext(code, { ...context, module, exports: module.exports }, { filename })
    return module.exports
  }
  return {
    storage, clock, presented,
    runtime: load(runtimeCode, "monitor_runtime.ts"),
    widget: load(widgetCode, "widget.tsx")
  }
}

function textContent(value) {
  if (value === null || value === undefined) return ""
  if (typeof value !== "object") return String(value)
  return (value.children ?? []).map(textContent).join("")
}

function successfulFetch(totalGB = 10, { delayEcs = false, clock, advanceBy = 0, calls = [] } = {}) {
  return async (_url, options) => {
    const action = new URLSearchParams(options.body).get("Action")
    calls.push(action)
    return {
      ok: true,
      status: 200,
      async json() {
        if (action === "ListCdtInternetTraffic") return { TrafficDetails: [{ Traffic: totalGB * 1024 ** 3 }] }
        assert.equal(action, "DescribeInstances", "Widgets must not query unrelated finance APIs.")
        if (delayEcs) await new Promise(resolve => setTimeout(resolve, 15))
        if (clock) clock.now += advanceBy
        return { Instances: { Instance: [{ Status: "Running", EipAddress: { IpAddress: "203.0.113.1" } }] } }
      }
    }
  }
}

test("snapshot identity uses every config field without exposing credentials", () => {
  const { runtime } = harness()
  const scope = runtime.configScope(config)
  assert.match(scope, /^[0-9a-f]{32}$/)
  assert.equal(scope.includes(config.accessKeyId), false)
  for (const [field, value] of Object.entries(config)) {
    assert.notEqual(runtime.configScope({ ...config, [field]: typeof value === "number" ? value + 1 : `${value}-other` }), scope, field)
  }
  assert.equal(runtime.accountHistoryScope({ ...config, ecsInstanceId: "other", accessKeySecret: "rotated" }),
    runtime.accountHistoryScope(config))
  assert.notEqual(runtime.accountHistoryScope({ ...config, accessKeyId: "other" }), runtime.accountHistoryScope(config))
})

test("snapshot rejects legacy, changed identity, expired, future, month and invalid data", () => {
  const { runtime } = harness()
  const now = dateAt(10, 12)
  const data = { totalGB: 12, updatedAt: now, ecsStatus: "Running" }
  const snapshot = runtime.createSnapshot(config, data, now)
  assert.equal(runtime.readSnapshot(JSON.stringify(snapshot), config, now).updatedAt.getTime(), now.getTime())
  assert.equal(runtime.readSnapshot(data, config, now), null)
  assert.equal(runtime.readSnapshot(snapshot, { ...config, ecsInstanceId: "other" }, now), null)
  assert.equal(runtime.readSnapshot(snapshot, config, new Date(now.getTime() + 6 * 3600000 + 1)), null)
  assert.equal(runtime.readSnapshot(snapshot, config, new Date(now.getTime() - 1)), null)
  assert.equal(runtime.readSnapshot({ ...snapshot, billingMonth: "2026-09" }, config, now), null)
  assert.equal(runtime.readSnapshot({ ...snapshot, data: { ...data, updatedAt: "bad" } }, config, now), null)
  assert.equal(runtime.readSnapshot({ ...snapshot, data: { ...data, totalGB: -1 } }, config, now), null)
  assert.equal(runtime.readSnapshot({ ...snapshot, data: { ...data, totalGB: Number.NaN } }, config, now), null)
  const lastMonth = dateAt(9, 30, 23)
  assert.equal(runtime.readSnapshot(runtime.createSnapshot(config, { totalGB: 5, updatedAt: lastMonth }, lastMonth), config, dateAt(10, 1, 0)), null)
})

test("refresh generation gate rejects previous refresh and invalidated work", () => {
  const { runtime } = harness()
  const gate = runtime.createRefreshGate()
  const first = gate.start()
  const second = gate.start()
  assert.equal(gate.isCurrent(first), false)
  assert.equal(gate.isCurrent(second), true)
  gate.invalidate()
  assert.equal(gate.isCurrent(second), false)
})

test("seven-day total requires seven complete consecutive daily deltas", () => {
  const { runtime } = harness()
  let points
  for (let day = 4; day <= 11; day++) points = runtime.recordTrafficSample(config, (day - 4) * 5, dateAt(10, day))
  assert.deepEqual(Array.from(points, point => point.valueGB), [5, 5, 5, 5, 5, 5, 5])
  assert.equal(runtime.sumCompleteSevenDays(points), 35)
  const missing = harness().runtime.recordTrafficSample(config, 5, dateAt(10, 11))
  assert.equal(runtime.sumCompleteSevenDays(missing), null)
  assert.equal(runtime.sumCompleteSevenDays(points.map((point, i) => i === 0 ? { ...point, valueGB: null } : point)), null)
})

test("missing day is not counted as zero or as a multi-day delta", () => {
  const { runtime } = harness()
  runtime.recordTrafficSample(config, 2, dateAt(10, 8))
  runtime.recordTrafficSample(config, 7, dateAt(10, 10))
  const points = runtime.recordTrafficSample(config, 10, dateAt(10, 11))
  assert.equal(points.find(point => point.date === "2026-10-09").valueGB, null)
  assert.equal(points.find(point => point.date === "2026-10-10").valueGB, null)
  assert.equal(points.find(point => point.date === "2026-10-11").valueGB, 3)
  assert.equal(runtime.sumCompleteSevenDays(points), null)
})

test("month rollover retains prior-month days and never differences across billing months", () => {
  const { runtime } = harness()
  for (let day = 24; day <= 30; day++) runtime.recordTrafficSample(config, day * 2, dateAt(9, day))
  const points = runtime.recordTrafficSample(config, 1, dateAt(10, 1))
  assert.deepEqual(Array.from(points, point => point.valueGB), [2, 2, 2, 2, 2, 2, null])
  assert.equal(runtime.sumCompleteSevenDays(points), null)
  assert.equal(runtime.recordTrafficSample(config, 4, dateAt(10, 2)).at(-1).valueGB, 3)
})

test("history stays isolated per account and refuses same-account late samples", () => {
  const { runtime, storage } = harness()
  runtime.recordTrafficSample(config, 20, dateAt(10, 12, 14))
  const before = [...storage.values()]
  runtime.recordTrafficSample(config, 9, dateAt(10, 12, 12))
  assert.deepEqual([...storage.values()], before)
  runtime.recordTrafficSample({ ...config, accessKeyId: "other" }, 100, dateAt(10, 12, 16))
  assert.equal(storage.size, 2)
  runtime.recordTrafficSample(config, 25, dateAt(10, 13))
  assert.equal(runtime.readDailyUsage(config, dateAt(10, 13)).at(-1).valueGB, 5)
})

test("counter decrease resets only the current month's baseline", () => {
  const { runtime } = harness()
  runtime.recordTrafficSample(config, 20, dateAt(9, 29))
  runtime.recordTrafficSample(config, 25, dateAt(9, 30))
  runtime.recordTrafficSample(config, 10, dateAt(10, 1))
  const points = runtime.recordTrafficSample(config, 1, dateAt(10, 2))
  assert.equal(points.find(point => point.date === "2026-09-30").valueGB, 5)
  assert.equal(points.at(-1).valueGB, null)
})

test("valid same-account legacy history migrates while malformed timestamps are discarded", () => {
  let hash = 2166136261
  for (const character of `${config.accessKeyId}|cdt`) {
    hash ^= character.charCodeAt(0)
    hash = Math.imul(hash, 16777619)
  }
  const storage = new Map([["aliyun_cdt_daily_history_v1", JSON.stringify({
    version: 1, scope: (hash >>> 0).toString(36), month: "2026-09",
    snapshots: [
      { date: "2026-09-29", totalGB: 20, updatedAt: dateAt(9, 29).getTime() },
      { date: "2026-09-30", totalGB: 25, updatedAt: dateAt(9, 30).getTime() },
      { date: "2026-09-28", totalGB: 2, updatedAt: dateAt(9, 29).getTime() }
    ]
  })]])
  const { runtime } = harness({ storage })
  const points = runtime.recordTrafficSample(config, 1, dateAt(10, 1))
  assert.equal(points.find(point => point.date === "2026-09-30").valueGB, 5)
  assert.equal(points.find(point => point.date === "2026-09-29").valueGB, null)
  assert.equal([...storage.keys()].filter(key => key.startsWith("aliyun_cdt_daily_history_v2_")).length, 1)
  assert.equal(runtime.readDailyUsage({ ...config, accessKeyId: "other" }, dateAt(10, 1)).every(point => point.valueGB === null), true)
})

test("request timeout includes response body parsing and supports unavailable AbortController", async () => {
  const { runtime } = harness({ noAbortController: true })
  await assert.rejects(runtime.withRequestTimeout(async signal => {
    assert.equal(signal, undefined)
    const response = { json: () => new Promise(() => {}) }
    return response.json()
  }, "BodyParse", 10), /BodyParse.*timed out/)
  assert.equal(await runtime.withRequestTimeout(async () => "ok", "Success", 10), "ok")
})

test("request deadline aborts an available controller", async () => {
  const { runtime } = harness()
  let signal
  await assert.rejects(runtime.withRequestTimeout(async value => {
    signal = value
    return new Promise(() => {})
  }, "HungRequest", 10), /HungRequest.*timed out/)
  assert.equal(signal.aborted, true)
})

test("widget saves an independent successful snapshot and then renders marked cache offline", async () => {
  const storage = new Map([[configKey, JSON.stringify(config)]])
  const online = harness({ storage, fetch: successfulFetch(12) })
  await online.widget.main()
  assert.equal(online.presented.length, 1)
  assert.match(textContent(online.presented[0].view), /12\.00/)
  assert.ok([...storage.keys()].some(key => key.startsWith(`${widgetKey}_`)), "widget snapshots are stored per account")
  assert.equal([...storage.keys()].some(key => key.startsWith(dashboardKey)), false)
  const offline = harness({ storage })
  await offline.widget.main()
  assert.equal(offline.presented.length, 1)
  assert.match(textContent(offline.presented[0].view), /CDT \u7f13\u5b58.*12\.00/)
  assert.equal(textContent(offline.presented[0].view).includes("\u83b7\u53d6\u5931\u8d25"), false)
})

test("widget uses a valid dashboard snapshot only after its own cache is absent or invalid", async () => {
  const storage = new Map([[configKey, JSON.stringify(config)]])
  const { runtime } = harness({ storage })
  const now = dateAt(10, 12)
  storage.set(dashboardKey, JSON.stringify(runtime.createSnapshot(config, { totalGB: 10, updatedAt: now, ecsStatus: "Running" }, now)))
  storage.set(widgetKey, JSON.stringify(runtime.createSnapshot({ ...config, ecsInstanceId: "other" }, { totalGB: 99, updatedAt: now }, now)))
  const offline = harness({ storage })
  await offline.widget.main()
  assert.match(textContent(offline.presented[0].view), /CDT \u7f13\u5b58.*10\.00/)
})

test("widget refuses wrong account, expired and unscoped fallback snapshots", async () => {
  for (const kind of ["account", "expired", "legacy"]) {
    const storage = new Map([[configKey, JSON.stringify(config)]])
    const { runtime } = harness({ storage })
    const now = dateAt(10, 12)
    const sampledAt = kind === "expired" ? new Date(now.getTime() - 7 * 3600000) : now
    const data = { totalGB: 12, updatedAt: sampledAt }
    const snapshot = kind === "legacy" ? data : runtime.createSnapshot(kind === "account" ? { ...config, accessKeyId: "other" } : config, data, now)
    storage.set(widgetKey, JSON.stringify(snapshot))
    const offline = harness({ storage })
    await offline.widget.main()
    assert.match(textContent(offline.presented[0].view), /\u83b7\u53d6\u5931\u8d25/)
  }
})

test("cache adapter recalculates reference fields and days using current config and time", () => {
  const { widget } = harness()
  const now = dateAt(10, 12)
  const adapted = widget.adaptDashboardSnapshotForWidget({
    totalGB: 10, thresholdGB: 999, vpsCutoffReferenceGB: 999,
    remainingGB: 999, daysRemaining: 99, updatedAt: now, ecsStatus: "Running"
  }, config, now)
  assert.equal(adapted.thresholdGB, 200)
  assert.equal(adapted.vpsCutoffReferenceGB, 195)
  assert.equal(adapted.remainingGB, 190)
  assert.equal(adapted.daysRemaining, 20)
  assert.equal(adapted.sevenDayTotalGB, null)
  assert.equal(adapted.isCached, true)
})

test("widget starts CDT and ECS in parallel and keeps the sample timestamp before slow ECS", async () => {
  const clock = { now: dateAt(10, 12).getTime() }
  const startedAt = clock.now
  const calls = []
  const { widget } = harness({
    clock,
    fetch: successfulFetch(12, { calls, clock, delayEcs: true, advanceBy: 10000 })
  })
  const data = await widget.fetchWidgetData(config)
  assert.deepEqual(calls, ["ListCdtInternetTraffic", "DescribeInstances"])
  assert.equal(data.updatedAt.getTime(), startedAt)
  assert.equal(data.ecsStatus, "Running")
})

test("widget handles an ECS-only timeout without losing successfully fetched traffic", async () => {
  const fetch = successfulFetch(12)
  const { widget } = harness({
    timeoutCap: 15,
    fetch: (url, options) => {
      const action = new URLSearchParams(options.body).get("Action")
      return action === "DescribeInstances" ? new Promise(() => {}) : fetch(url, options)
    }
  })
  const data = await widget.fetchWidgetData(config)
  assert.equal(data.totalGB, 12)
  assert.equal(data.ecsStatus, "Unknown")
})

test("widget rejects a response crossing the billing month without persisting history", async () => {
  const clock = { now: dateAt(9, 30, 23).getTime() }
  const { widget, storage, runtime } = harness({
    clock,
    fetch: successfulFetch(1, { clock, advanceBy: 3600000 })
  })
  await assert.rejects(widget.fetchWidgetData(config), /Billing month changed/)
  assert.equal(storage.size, 0)
  assert.throws(() => runtime.assertSampleBillingMonth(dateAt(9, 30), dateAt(10, 1)), /Billing month changed/)
})
