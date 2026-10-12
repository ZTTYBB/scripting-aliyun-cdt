import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { createRequire } from "node:module"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { spawnSync } from "node:child_process"
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
      if (existsSync(metadata)
        && JSON.parse(readFileSync(metadata, "utf8")).version === "0.25.0") {
        return require(path)
      }
    }
  }
  return null
}

const esbuild = cachedEsbuild()
function transpile(source, path) {
  if (esbuild) {
    return esbuild.transformSync(source, {
      sourcefile: path, loader: "ts", format: "cjs", target: "es2020"
    }).code
  }
  const args = [
    "--yes", "esbuild@0.25.0", "--loader=ts", "--format=cjs", "--target=es2020"
  ]
  const result = process.platform === "win32"
    ? spawnSync("powershell.exe", [
      "-NoProfile", "-NonInteractive", "-Command", `npx ${args.join(" ")}`
    ], { input: source, encoding: "utf8", cwd: projectRoot })
    : spawnSync("npx", args, { input: source, encoding: "utf8", cwd: projectRoot })
  if (result.error) throw result.error
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

const compiled = new Map()
function loadModule(name, overrides = {}, modules = new Map()) {
  if (modules.has(name)) return modules.get(name).exports
  const path = join(projectRoot, `${name}.ts`)
  if (!compiled.has(name)) compiled.set(name, transpile(readFileSync(path, "utf8"), path))
  const module = { exports: {} }
  modules.set(name, module)
  vm.runInNewContext(compiled.get(name), {
    module, exports: module.exports, console,
    setTimeout, clearTimeout, AbortController, Date, ...overrides,
    require(importName) {
      if (importName === "scripting") return { Storage: { get: () => null } }
      assert.match(importName, /^\.\//)
      return loadModule(importName.slice(2), overrides, modules)
    }
  }, { filename: path })
  return module.exports
}

const { isBillQueryAvailable, queryAccountBillPages, recentBillingDates } = loadModule("bill_queries")
const normalize = value => JSON.parse(JSON.stringify(value))
const response = (items, extra = {}) => ({
  Success: true, Code: "Success", Data: { Items: { Item: items }, ...extra }
})
const rows = (count, start = 0) => Array.from({ length: count }, (_, index) => ({
  id: index + start, PipCode: "ecs", PretaxAmount: "1.00"
}))

test("bill availability requires a real item array and a successful business response", () => {
  for (const invalid of [
    null, undefined, {}, { Data: {} }, { Data: { Items: {} } },
    { Data: { Items: { Item: null } } }, { Data: { Items: { Item: {} } } },
    { ...response([]), Success: false }, { ...response([]), Code: "Forbidden" }
  ]) assert.equal(isBillQueryAvailable(invalid), false)
  assert.equal(isBillQueryAvailable(response([])), true)
  assert.equal(isBillQueryAvailable({ Data: { Items: { Item: [] } } }), true)
})

test("all 301 rows are collected from both pages using TotalCount", async () => {
  const requests = []
  const result = await queryAccountBillPages(async params => {
    requests.push(params)
    return response(params.PageNum === 1 ? rows(300) : rows(1, 300), {
      TotalCount: "301", PageNum: String(params.PageNum)
    })
  }, { BillingCycle: "2026-10", IsGroupByProduct: true })
  assert.equal(result.available, true)
  assert.equal(result.items.length, 301)
  assert.equal(result.items[300].id, 300)
  assert.deepEqual(requests.map(params => params.PageNum), [1, 2])
  assert.ok(requests.every(params => params.PageSize === 300
    && params.BillingCycle === "2026-10" && params.IsGroupByProduct === true))
})

test("a full page without TotalCount needs the next short page", async () => {
  const pages = []
  const result = await queryAccountBillPages(async params => {
    pages.push(params.PageNum)
    return response(params.PageNum === 1 ? rows(300) : [])
  }, {})
  assert.equal(result.available, true)
  assert.equal(result.items.length, 300)
  assert.deepEqual(pages, [1, 2])
})

test("missing metadata does not truncate a nonempty second page", async () => {
  const result = await queryAccountBillPages(
    async params => response(params.PageNum === 1 ? rows(300) : rows(1, 300)), {}
  )
  assert.equal(result.available, true)
  assert.equal(result.items.length, 301)
})

test("complete empty records are valid, but absent records are unavailable", async () => {
  const empty = await queryAccountBillPages(async () => response([], { TotalCount: 0 }), {})
  assert.deepEqual(normalize(empty), { available: true, items: [] })
  for (const invalid of [
    { Success: true, Data: {} }, { Success: false, Data: { Items: { Item: [] } } },
    { Data: { Items: { Item: [] }, TotalCount: 1 } }
  ]) {
    const result = await queryAccountBillPages(async () => invalid, {})
    assert.deepEqual(normalize(result), { available: false, items: [] })
  }
})

test("a failed second page invalidates the complete result instead of returning partial money", async () => {
  for (const failure of [
    { ...response([]), Success: false }, { ...response([]), Code: "Forbidden" },
    { Data: {} }, new Error("offline")
  ]) {
    const result = await queryAccountBillPages(async params => {
      if (params.PageNum === 1) return response(rows(300), { TotalCount: 301 })
      if (failure instanceof Error) throw failure
      return failure
    }, {})
    assert.deepEqual(normalize(result), { available: false, items: [] })
  }
})

test("repeated pages, wrong page numbers, changing totals and no progress are rejected", async () => {
  const cases = [
    params => response(rows(2), { TotalCount: 4 }),
    params => response(params.PageNum === 1 ? rows(2) : rows(2).reverse(), { TotalCount: 4 }),
    params => response(rows(2, (params.PageNum - 1) * 2), { TotalCount: 4, PageNum: 1 }),
    params => response(rows(2, (params.PageNum - 1) * 2), { TotalCount: 4, PageSize: 1 }),
    params => response(rows(2, (params.PageNum - 1) * 2), { TotalCount: params.PageNum === 1 ? 4 : 5 }),
    params => response(params.PageNum === 1 ? rows(2) : [], { TotalCount: 4 })
  ]
  for (const mock of cases) {
    const result = await queryAccountBillPages(async params => mock(params), {}, { pageSize: 2 })
    assert.deepEqual(normalize(result), { available: false, items: [] })
  }
})

test("unconfirmed full pages at the page limit are unavailable", async () => {
  const result = await queryAccountBillPages(
    async params => response(rows(2, params.PageNum * 2)), {}, { pageSize: 2, maxPages: 2 }
  )
  assert.deepEqual(normalize(result), { available: false, items: [] })
})

test("invalid total counts and oversized totals never become complete results", async () => {
  for (const total of [null, "", "invalid", -1, 1.5, "1.5", 301, 1]) {
    const result = await queryAccountBillPages(
      async () => response(rows(2), { TotalCount: total }), {},
      { pageSize: 2, maxPages: 2 }
    )
    assert.deepEqual(normalize(result), { available: false, items: [] })
  }
})

test("a hung page is bounded and cannot start later pages after the deadline", async () => {
  let resolvePage
  let calls = 0
  const result = await queryAccountBillPages(() => {
    calls++
    return new Promise(resolve => { resolvePage = resolve })
  }, {}, { pageSize: 2, timeoutMs: 10 })
  assert.deepEqual(normalize(result), { available: false, items: [] })
  resolvePage(response(rows(2), { TotalCount: 4 }))
  await new Promise(resolve => setTimeout(resolve, 5))
  assert.equal(calls, 1)
})

test("the recent seven dates include the previous month with its own cycle", () => {
  const dates = recentBillingDates(new Date(2026, 9, 1, 12))
  assert.deepEqual(Array.from(dates, item => item.dateStr), [
    "2026-10-01", "2026-09-30", "2026-09-29", "2026-09-28",
    "2026-09-27", "2026-09-26", "2026-09-25"
  ])
  assert.deepEqual(Array.from(dates, item => item.billingCycle), [
    "2026-10", "2026-09", "2026-09", "2026-09", "2026-09", "2026-09", "2026-09"
  ])
  assert.equal(dates[0].isToday, true)
  assert.ok(dates.slice(1).every(item => !item.isToday))
})

test("recent billing dates cross year and leap-day boundaries", () => {
  const year = recentBillingDates(new Date(2027, 0, 1), 2)
  assert.deepEqual(normalize(year), [
    { dateStr: "2027-01-01", displayDate: "01-01", isToday: true, billingCycle: "2027-01" },
    { dateStr: "2026-12-31", displayDate: "12-31", isToday: false, billingCycle: "2026-12" }
  ])
  const leap = recentBillingDates(new Date(2028, 2, 1), 2)
  assert.equal(leap[1].dateStr, "2028-02-29")
})

function serviceFixture(now, responder) {
  class FixedDate extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now.getTime()]))
    }
    static now() { return now.getTime() }
  }
  const requests = []
  const { AliyunService } = loadModule("aliyun", {
    Date: FixedDate,
    async fetch(_url, options) {
      const params = Object.fromEntries(new URLSearchParams(options.body))
      requests.push(params)
      return { ok: true, json: async () => responder(params), text: async () => "" }
    }
  })
  const service = new AliyunService({
    accessKeyId: "test-key", accessKeySecret: "test-secret", regionId: "cn-hongkong",
    ecsInstanceId: "i-test", trafficThresholdGB: 200, vpsCutoffReferenceGB: 195,
    resetDayOfMonth: 1
  })
  return { service, requests }
}

test("monthly account-bill fallback aggregates every page and recent daily dates cross months", async () => {
  const { service, requests } = serviceFixture(new Date(2026, 9, 1, 12), params => {
    if (params.Action === "QueryBillOverview") return { Success: false, Code: "Forbidden" }
    if (params.Granularity === "DAILY") return response([])
    return response(params.PageNum === "1" ? rows(300) : rows(1, 300), {
      TotalCount: 301, PageNum: params.PageNum
    })
  })
  const bill = await service.getMonthlyBill()
  assert.equal(bill.paymentAmount, "301.00")
  assert.equal(bill.hasRecords, true)
  assert.equal(bill.ecsAmount, "301.00")
  assert.equal(bill.ecsDailyList.length, 7)
  const monthPages = requests.filter(item => item.Action === "QueryAccountBill" && !item.Granularity)
  assert.deepEqual(monthPages.map(item => item.PageNum), ["1", "2"])
  const daily = requests.filter(item => item.Granularity === "DAILY")
  assert.equal(daily.length, 7)
  assert.ok(daily.every(item => item.BillingCycle === item.BillingDate.slice(0, 7)))
  assert.equal(daily.filter(item => item.BillingCycle === "2026-09").length, 6)
})

test("an empty monthly overview checks the account bill before confirming zero", async () => {
  const { service, requests } = serviceFixture(new Date(2026, 9, 1), () => response([]))
  const bill = await service.getMonthlyBill()
  assert.equal(bill.paymentAmount, "0.00")
  assert.equal(bill.hasRecords, false)
  assert.equal(bill.outstandingAmount, "0.00")
  assert.equal(bill.ecsDailyList.length, 7)
  assert.equal(requests.filter(item => item.Action === "QueryAccountBill" && !item.Granularity).length, 1)
})

test("an empty overview can still have account bill records", async () => {
  const { service } = serviceFixture(new Date(2026, 9, 1), params => {
    if (params.Action === "QueryBillOverview" || params.Granularity === "DAILY") return response([])
    return response([{ PipCode: "ecs", PretaxAmount: "7.25" }])
  })
  assert.equal((await service.getMonthlyBill()).paymentAmount, "7.25")
})

test("an empty overview with failed account fallback stays unavailable", async () => {
  const { service } = serviceFixture(new Date(2026, 9, 1), params => {
    if (params.Action === "QueryBillOverview") return response([])
    return { Success: false, Code: "Forbidden" }
  })
  assert.equal(await service.getMonthlyBill(), null)
})

test("an empty current month retains previous month daily records in the seven-day window", async () => {
  const { service } = serviceFixture(new Date(2026, 9, 1), params => {
    if (params.Granularity === "DAILY" && params.BillingCycle === "2026-09") {
      return response([{ PipCode: "ecs", PretaxAmount: "2.50" }])
    }
    return response([])
  })
  const bill = await service.getMonthlyBill()
  assert.equal(bill.hasRecords, false)
  assert.equal(bill.paymentAmount, "0.00")
  assert.equal(bill.ecsDailyList.length, 7)
  assert.equal(bill.ecsDailyList[0].settled, false)
  assert.ok(bill.ecsDailyList.slice(1).every(item => item.amount === "2.50" && item.settled))
})

test("monthly partial pagination returns unavailable, never a partial total", async () => {
  const { service } = serviceFixture(new Date(2026, 9, 1), params => {
    if (params.Action === "QueryBillOverview") return { Success: false }
    return params.PageNum === "1"
      ? response(rows(300), { TotalCount: 301 })
      : { Success: false, Code: "Forbidden" }
  })
  assert.equal(await service.getMonthlyBill(), null)
})

test("daily queries collect both pages and do not mark a failed page as settled zero", async () => {
  const { service } = serviceFixture(new Date(2027, 0, 1), params => {
    if (params.Action === "QueryBillOverview") return response([{ PipCode: "ecs", PretaxAmount: "1" }])
    if (params.BillingDate === "2027-01-01") {
      return response(params.PageNum === "1" ? rows(300) : rows(1, 300), { TotalCount: 301 })
    }
    if (params.BillingDate === "2026-12-31") {
      return params.PageNum === "1"
        ? response(rows(300), { TotalCount: 301 })
        : { Success: false, Code: "Forbidden" }
    }
    return response([])
  })
  const bill = await service.getMonthlyBill()
  assert.equal(bill.ecsDailyList[0].amount, "301.00")
  assert.equal(bill.ecsDailyList[0].settled, true)
  assert.equal(bill.ecsDailyList[1].amount, "0.00")
  assert.equal(bill.ecsDailyList[1].settled, false)
  assert.equal(bill.ecsDailyList[1].date, "12-31")
})
