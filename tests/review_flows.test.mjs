import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { createRequire } from "node:module"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import test from "node:test"
import vm from "node:vm"

const require = createRequire(import.meta.url)
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const configKey = "aliyun_cdt_monitor_config"
const snapshotKey = "aliyun_cdt_dashboard_cache"
const widgetSnapshotKey = "aliyun_cdt_widget_cache"
const privacyKey = "aliyun_cdt_privacy_mode"
const labels = {
  settings: "\u8bbe\u7f6e",
  refresh: "\u5237\u65b0\u6570\u636e",
  hide: "\u9690\u85cf\u91d1\u989d",
  show: "\u663e\u793a\u91d1\u989d",
  failed: "\u83b7\u53d6\u5931\u8d25",
  cached: "\u7f13\u5b58"
}
const oldConfig = {
  accessKeyId: "old-test-key", accessKeySecret: "old-test-secret", regionId: "cn-hongkong",
  ecsInstanceId: "i-old-test", trafficThresholdGB: 200, vpsCutoffReferenceGB: 195,
  resetDayOfMonth: 1
}
const newConfig = {
  ...oldConfig, accessKeyId: "new-test-key", accessKeySecret: "new-test-secret",
  ecsInstanceId: "i-new-test", regionId: "cn-shanghai"
}

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
      if (existsSync(metadata)
        && JSON.parse(readFileSync(metadata, "utf8")).version === "0.25.0") {
        return require(path)
      }
    }
  }
  throw new Error("The pinned esbuild@0.25.0 test tool must already be cached; tests never use the network.")
}

const esbuild = cachedEsbuild()
const compiledSources = new Map()
const entryPoints = [
  {
    file: "index.tsx", root: "ConsoleView", fetch: "fetchConsoleData", settings: "SettingsView",
    slots: { config: 0, data: 3, loading: 5, error: 6, logs: 7 }
  },
  {
    file: "AliyunCDT_AllInOne.tsx", root: "AppDashboard", fetch: "fetchMonitorData",
    settings: "SettingsComponent",
    slots: { config: 0, data: 3, loading: 4, error: 5 }
  }
]

function deferred() {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function jsx(type, props, ...children) {
  const flattened = children.flat(Infinity)
    .filter(child => child !== undefined && child !== null && child !== false)
  return {
    type,
    props: { ...props, children: flattened.length === 1 ? flattened[0] : flattened },
    children: flattened
  }
}

function descendants(tree) {
  const result = []
  const seen = new Set()
  const visit = value => {
    if (!value || typeof value !== "object" || seen.has(value)) return
    seen.add(value)
    if ("type" in value && "props" in value) result.push(value)
    for (const child of Object.values(value)) visit(child)
  }
  visit(tree)
  return result
}

function textContent(node) {
  if (node === null || node === undefined || node === false) return ""
  if (typeof node !== "object") return typeof node === "function" ? "" : String(node)
  return (node.children ?? []).map(textContent).join("")
}

function screenText(tree) {
  return descendants(tree).filter(node => node.type === "Text").map(textContent).join("\n")
}

function button(tree, label) {
  const result = descendants(tree).find(node =>
    node.type === "Button" && node.props.accessibilityLabel === label)
  assert.ok(result, `Missing ${label} button`)
  return result.props
}

function hooks() {
  const slots = []
  const effectSlots = []
  let cursor = 0
  let effectCursor = 0
  let pendingEffects = []
  return {
    slots,
    useState(initial) {
      const index = cursor++
      if (!(index in slots)) {
        slots[index] = {
          value: typeof initial === "function" ? initial() : initial,
          set(next) {
            slots[index].value = typeof next === "function" ? next(slots[index].value) : next
          }
        }
      }
      return [slots[index].value, slots[index].set]
    },
    useCallback: callback => callback,
    useEffect(effect, dependencies) {
      const index = effectCursor++
      if (!(index in effectSlots)) {
        effectSlots[index] = { dependencies, cleanup: undefined }
        pendingEffects.push(() => {
          effectSlots[index].cleanup = effect()
        })
      }
    },
    render(component) {
      cursor = 0
      effectCursor = 0
      return component()
    },
    commitEffects() {
      const effects = pendingEffects
      pendingEffects = []
      effects.forEach(effect => effect())
    },
    cleanup() {
      effectSlots.forEach(effect => effect.cleanup?.())
    }
  }
}

const billResponse = items => ({
  Success: true, Code: "Success", Data: { Items: { Item: items }, TotalCount: items.length }
})
const trafficResponse = totalGB => ({ TrafficDetails: [{ Traffic: totalGB * 1024 ** 3 }] })

function defaultResponse(params) {
  const isNew = params.AccessKeyId === newConfig.accessKeyId
  if (params.Action === "ListCdtInternetTraffic") return trafficResponse(isNew ? 22 : 11)
  if (params.Action === "DescribeInstances") {
    return {
      Instances: {
        Instance: [{
          InstanceId: isNew ? newConfig.ecsInstanceId : oldConfig.ecsInstanceId,
          Status: "Running",
          EipAddress: { IpAddress: isNew ? "198.51.100.20" : "198.51.100.10" }
        }]
      }
    }
  }
  if (params.Action === "QueryAccountBalance") {
    const amount = isNew ? "987.65" : "123.45"
    return { Data: { AvailableAmount: amount, AvailableCashAmount: amount, Currency: "CNY" } }
  }
  if (params.Action === "QueryBillOverview" || params.Action === "QueryAccountBill") {
    return billResponse([{ PipCode: "ecs", PretaxAmount: "1.00" }])
  }
  throw new Error(`Unexpected mocked API action: ${params.Action}`)
}

function fixture(entry, options = {}) {
  const hookHost = hooks()
  const values = new Map([[configKey, JSON.stringify(oldConfig)]])
  const writes = []
  const storage = {
    get: key => values.get(key),
    set(key, value) {
      values.set(key, value)
      writes.push([key, value])
    }
  }
  let timestamp = (options.now ?? new Date(2026, 9, 12, 12)).getTime()
  class FixedDate extends Date {
    constructor(...args) { super(...(args.length ? args : [timestamp])) }
    static now() { return timestamp }
  }
  const requests = []
  const presented = []
  const timers = new Set()
  const widget = {
    family: options.widgetFamily,
    displaySize: { width: 329, height: 155 },
    present(element, policy) { presented.push({ element, policy }) }
  }
  const scripting = new Proxy({
    useState: hookHost.useState,
    useEffect: hookHost.useEffect,
    useCallback: hookHost.useCallback,
    Widget: widget,
    Storage: storage,
    Navigation: { present: async options => presented.push(options) },
    Script: { exit() {} }
  }, { get: (target, name) => name in target ? target[name] : String(name) })
  const context = vm.createContext({
    console: { log() {}, error() {}, warn() {} },
    Date: FixedDate, AbortController, Storage: storage, Widget: widget,
    __jsx: jsx, __fragment: "Fragment",
    setTimeout(callback, delay, ...args) {
      const id = setTimeout(() => {
        timers.delete(id)
        callback(...args)
      }, delay)
      timers.add(id)
      return id
    },
    clearTimeout(id) {
      timers.delete(id)
      clearTimeout(id)
    },
    async fetch(url, requestOptions) {
      assert.match(url, /^https:\/\/(?:cdt|business|ecs\.[a-z0-9-]+)\.aliyuncs\.com\/$/)
      assert.equal(requestOptions?.method, "POST")
      const params = Object.fromEntries(new URLSearchParams(requestOptions.body))
      requests.push(params)
      return {
        ok: true, status: 200,
        json: async () => (options.respond ?? defaultResponse)(params),
        text: async () => ""
      }
    }
  })
  const modules = new Map()
  const load = file => {
    if (modules.has(file)) return modules.get(file).exports
    const path = join(projectRoot, file)
    let source = readFileSync(path, "utf8")
    if (file === entry.file) {
      assert.match(source, /\bmain\(\)\s*$/)
      source = source.replace(/\bmain\(\)\s*$/, "")
      source += `\nexport { ${entry.root}, ${entry.fetch}, main, createSnapshot };\n`
    }
    const cacheKey = `${file}\0${source}`
    if (!compiledSources.has(cacheKey)) {
      compiledSources.set(cacheKey, esbuild.transformSync(source, {
        sourcefile: path,
        loader: file.endsWith(".tsx") ? "tsx" : "ts",
        format: "cjs", target: "es2020", jsxFactory: "__jsx", jsxFragment: "__fragment"
      }).code)
    }
    const module = { exports: {} }
    modules.set(file, module)
    const loader = importName => {
      if (importName === "scripting") return scripting
      assert.ok(["./monitor_runtime", "./bill_queries"].includes(importName),
        `Unexpected production import ${importName}`)
      return load(`${importName.slice(2)}.ts`)
    }
    const wrap = new vm.Script(`(function (module, exports, require) {\n${compiledSources.get(cacheKey)}\n})`,
      { filename: path })
    wrap.runInContext(context)(module, module.exports, loader)
    return module.exports
  }
  const exports = load(entry.file)
  return {
    entry, exports, values, writes, requests, presented, storage, hooks: hookHost,
    render: () => hookHost.render(exports[entry.root]),
    state: name => hookHost.slots[entry.slots[name]]?.value,
    setTime: now => { timestamp = now.getTime() },
    dispose() {
      hookHost.cleanup()
      for (const timer of timers) clearTimeout(timer)
      timers.clear()
    }
  }
}

async function flushUntil(predicate, message = "The expected mocked flow did not settle") {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (predicate()) return
    await new Promise(resolve => setImmediate(resolve))
  }
  assert.ok(predicate(), message)
}

function saveNewConfig(host) {
  button(host.render(), labels.settings).action()
  const settings = descendants(host.render()).find(node =>
    typeof node.type === "function" && node.type.name === host.entry.settings)
  assert.ok(settings, `Missing ${host.entry.settings}`)
  settings.props.onSave(newConfig)
}

function assertAcceptedNewData(host) {
  assert.equal(host.state("config").accessKeyId, newConfig.accessKeyId)
  assert.equal(host.state("data").totalGB, 22)
  assert.equal(host.state("data").publicIp, "198.51.100.20")
  assert.equal(host.state("data").financialBalance.availableCashAmount, "987.65")
  assert.equal(host.state("error"), null)
  assert.equal(host.state("loading"), false)
  const snapshot = JSON.parse(host.values.get(snapshotKey))
  assert.equal(snapshot.data.totalGB, 22)
  assert.equal(snapshot.data.publicIp, "198.51.100.20")
  const histories = [...host.values.entries()].filter(([key]) => key.startsWith("aliyun_cdt_daily_history_v2_"))
  assert.equal(histories.length, 1, "Only the accepted account may record a traffic history sample.")
  assert.equal(JSON.parse(histories[0][1]).snapshots.at(-1).totalGB, 22)
}

for (const entry of entryPoints) {
  for (const completion of ["resolve", "reject"]) {
    test(`${entry.file}: a late old-account ${completion} cannot replace new data, cache, history or error`, async t => {
      const oldTraffic = deferred()
      const newTraffic = deferred()
      const host = fixture(entry, {
        respond: params => params.Action === "ListCdtInternetTraffic"
          ? (params.AccessKeyId === oldConfig.accessKeyId ? oldTraffic.promise : newTraffic.promise)
          : defaultResponse(params)
      })
      t.after(() => host.dispose())
      host.render()
      host.hooks.commitEffects()
      await flushUntil(() => host.requests.some(request => request.AccessKeyId === oldConfig.accessKeyId))
      assert.equal(host.state("loading"), true)
      saveNewConfig(host)
      assert.equal(host.state("data"), null)
      assert.equal(host.state("error"), null)
      assert.equal(host.state("loading"), true)
      newTraffic.resolve(trafficResponse(22))
      await flushUntil(() => host.state("loading") === false)
      assertAcceptedNewData(host)
      const acceptedStorage = [...host.values.entries()]
      const writes = host.writes.length
      if (completion === "resolve") oldTraffic.resolve(trafficResponse(11))
      else oldTraffic.reject(new Error("late-old-account-failure"))
      await new Promise(resolve => setImmediate(resolve))
      await new Promise(resolve => setImmediate(resolve))
      assertAcceptedNewData(host)
      assert.deepEqual([...host.values.entries()], acceptedStorage)
      assert.equal(host.writes.length, writes, "A stale completion must not write any snapshot or history.")
      assert.doesNotMatch(screenText(host.render()), /late-old-account-failure|198\.51\.100\.10|123\.45/)
    })
  }

  test(`${entry.file}: the old request's finally cannot clear a newer pending loading state`, async t => {
    const oldTraffic = deferred()
    const newTraffic = deferred()
    const host = fixture(entry, {
      respond: params => params.Action === "ListCdtInternetTraffic"
        ? (params.AccessKeyId === oldConfig.accessKeyId ? oldTraffic.promise : newTraffic.promise)
        : defaultResponse(params)
    })
    t.after(() => host.dispose())
    host.render()
    host.hooks.commitEffects()
    await flushUntil(() => host.requests.some(request => request.Action === "ListCdtInternetTraffic"))
    saveNewConfig(host)
    oldTraffic.reject(new Error("stale-old-error"))
    await new Promise(resolve => setImmediate(resolve))
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(host.state("loading"), true)
    assert.equal(button(host.render(), labels.refresh).disabled, true)
    assert.equal(host.state("error"), null)
    assert.equal(host.state("data"), null)
    newTraffic.resolve(trafficResponse(22))
    await flushUntil(() => host.state("loading") === false)
    assertAcceptedNewData(host)
  })

  test(`${entry.file}: changing configuration immediately clears cached old IP, balance and errors`, async t => {
    let phase = "success"
    const newTraffic = deferred()
    const host = fixture(entry, {
      respond(params) {
        if (params.Action === "ListCdtInternetTraffic" && phase === "failure") {
          throw new Error("old-account-visible-error")
        }
        if (params.Action === "ListCdtInternetTraffic" && params.AccessKeyId === newConfig.accessKeyId) {
          return newTraffic.promise
        }
        return defaultResponse(params)
      }
    })
    t.after(() => host.dispose())
    host.render()
    host.hooks.commitEffects()
    await flushUntil(() => host.state("data") !== null && host.state("loading") === false)
    assert.match(screenText(host.render()), /123\.45|198\.51\.100\.10/)
    phase = "failure"
    await button(host.render(), labels.refresh).action()
    assert.match(host.state("error"), /old-account-visible-error/)
    assert.equal(host.state("data").isCached, true)
    phase = "success"
    saveNewConfig(host)
    assert.equal(host.state("data"), null)
    assert.equal(host.state("error"), null)
    assert.equal(host.state("loading"), true)
    assert.doesNotMatch(screenText(host.render()), /old-account-visible-error|123\.45|198\.51\.100\.10/)
    if (entry.slots.logs !== undefined) {
      assert.ok(host.state("logs").every(entry => !/123\.45|198\.51\.100\.10|old-account/.test(entry.line)))
    }
    newTraffic.resolve(trafficResponse(22))
    await flushUntil(() => host.state("loading") === false)
    assert.equal(host.state("data").publicIp, "198.51.100.20")
  })

  test(`${entry.file}: real monthly fetch preserves seven daily rows when the current month is empty`, async t => {
    const host = fixture(entry, {
      now: new Date(2026, 9, 1, 12),
      respond(params) {
        if (params.Action === "QueryBillOverview") return billResponse([])
        if (params.Action === "QueryAccountBill") {
          return params.Granularity === "DAILY" && params.BillingCycle === "2026-09"
            ? billResponse([{ PipCode: "ecs", PretaxAmount: "2.50" }])
            : billResponse([])
        }
        return defaultResponse(params)
      }
    })
    t.after(() => host.dispose())
    const data = await host.exports[entry.fetch](oldConfig)
    assert.equal(data.financialBillStatus, "available")
    assert.equal(data.financialBill.hasRecords, false)
    assert.equal(data.financialBill.paymentAmount, "0.00")
    const daily = data.financialBill.ecsDailyList
    assert.equal(daily.length, 7)
    assert.equal(daily[0].date, "10-01")
    assert.equal(daily[0].settled, false)
    assert.equal(daily[0].available, true)
    assert.ok(daily.slice(1).every(item => item.amount === "2.50" && item.available && item.settled))
    assert.equal(daily.at(-1).date, "09-25")
    const requests = host.requests.filter(request => request.Granularity === "DAILY")
    assert.equal(requests.length, 7)
    assert.ok(requests.every(request => request.BillingCycle === request.BillingDate.slice(0, 7)))
  })
}

test("index.tsx: toggling privacy hides existing and fresh financial log entries, and showing restores them", async t => {
  let amount = "123.45"
  const host = fixture(entryPoints[0], {
    respond(params) {
      if (params.Action === "QueryAccountBalance") {
        return { Data: { AvailableCashAmount: amount, AvailableAmount: amount, Currency: "CNY" } }
      }
      return defaultResponse(params)
    }
  })
  t.after(() => host.dispose())
  host.render()
  host.hooks.commitEffects()
  await flushUntil(() => host.state("data") !== null && host.state("loading") === false)
  assert.ok(host.state("logs").some(entry => entry.financial && entry.line.includes("123.45")))
  assert.match(screenText(host.render()), /123\.45/)
  button(host.render(), labels.hide).action()
  assert.equal(host.values.get(privacyKey), "true")
  assert.doesNotMatch(screenText(host.render()), /123\.45/)
  assert.match(screenText(host.render()), /\*{4}/)
  amount = "234.56"
  await button(host.render(), labels.refresh).action()
  assert.ok(host.state("logs").some(entry => entry.financial && entry.line.includes("234.56")))
  assert.doesNotMatch(screenText(host.render()), /123\.45|234\.56/)
  button(host.render(), labels.show).action()
  assert.equal(host.values.get(privacyKey), "false")
  assert.match(screenText(host.render()), /123\.45/)
  assert.match(screenText(host.render()), /234\.56/)
})

test("AllInOne widget main never calls financial APIs, saves its own snapshot, and reuses it offline", async t => {
  let offline = false
  const host = fixture(entryPoints[1], {
    widgetFamily: "accessoryInline",
    respond(params) {
      if (params.Action.startsWith("Query")) return new Promise(() => {})
      if (offline) throw new Error("mock-offline")
      return defaultResponse(params)
    }
  })
  t.after(() => host.dispose())
  host.storage.set(snapshotKey, "independent-dashboard-sentinel")
  let deadline
  try {
    await Promise.race([
      host.exports.main(),
      new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error("Widget main was blocked")), 500) })
    ])
  } finally {
    clearTimeout(deadline)
  }
  assert.deepEqual(host.requests.map(request => request.Action).sort(), ["DescribeInstances", "ListCdtInternetTraffic"])
  assert.equal(host.values.get(snapshotKey), "independent-dashboard-sentinel")
  const snapshot = JSON.parse(host.values.get(widgetSnapshotKey))
  assert.equal(snapshot.version, 2)
  assert.equal(snapshot.data.totalGB, 11)
  assert.equal(host.presented.length, 1)
  assert.equal(host.presented[0].element.props.data.totalGB, 11)
  offline = true
  await host.exports.main()
  assert.equal(host.presented.length, 2)
  const cached = host.presented[1].element
  assert.equal(cached.props.data.totalGB, 11)
  assert.equal(cached.props.data.isCached, true)
  assert.match(screenText(cached.type(cached.props)), new RegExp(labels.cached))
  assert.equal(host.values.get(snapshotKey), "independent-dashboard-sentinel")
  host.storage.set(configKey, JSON.stringify(newConfig))
  await host.exports.main()
  assert.equal(host.presented.length, 3)
  assert.match(screenText(host.presented[2].element), new RegExp(labels.failed))
  assert.doesNotMatch(screenText(host.presented[2].element), /11\.00/)
})
