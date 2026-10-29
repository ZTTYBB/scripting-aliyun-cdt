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
      if (existsSync(metadata) && JSON.parse(readFileSync(metadata, "utf8")).version === "0.25.0") return require(path)
    }
  }
  throw new Error("Install esbuild@0.25.0 or reuse the existing npx cache before running the tests.")
}

const esbuild = cachedEsbuild()
const runtimeCode = esbuild.transformSync(readFileSync(join(projectRoot, "monitor_runtime.ts"), "utf8"), {
  loader: "ts", format: "cjs", target: "es2020"
}).code
const widgetCode = esbuild.buildSync({
  stdin: {
    contents: readFileSync(join(projectRoot, "widget.tsx"), "utf8").replace(/\bmain\(\)\s*$/, "export { main }"),
    loader: "tsx", resolveDir: projectRoot, sourcefile: "widget.tsx"
  },
  bundle: true, write: false, format: "cjs", target: "es2020",
  external: ["scripting"], jsxFactory: "__jsx", jsxFragment: "__fragment"
}).outputFiles[0].text

const base = {
  regionId: "cn-hongkong", trafficThresholdGB: 200, vpsCutoffReferenceGB: 195, resetDayOfMonth: 1
}
const domestic = { ...base, id: "acct_cn", name: "国内", site: "cn", accessKeyId: "ak-cn", accessKeySecret: "sk-cn", ecsInstanceId: "i-cn" }
const overseas = {
  ...base, id: "acct_intl", name: "国外", site: "intl", regionId: "ap-southeast-1",
  accessKeyId: "ak-intl", accessKeySecret: "sk-intl", ecsInstanceId: "i-intl"
}

function load(storage = new Map(), { parameter, family = "systemMedium", fetch } = {}) {
  const presented = []
  const urls = []
  const scripting = new Proxy({
    Widget: {
      family, parameter, displaySize: { width: 329, height: 155 },
      present(view) { presented.push(view) }
    }
  }, { get: (target, name) => name in target ? target[name] : String(name) })
  const context = {
    Date, AbortController, setTimeout, clearTimeout,
    Storage: { get: key => storage.get(key), set: (key, value) => storage.set(key, value) },
    console: { log() {}, warn() {}, error() {} },
    fetch: async (url, options) => {
      urls.push(url)
      return fetch(url, Object.fromEntries(new URLSearchParams(options.body)))
    },
    __jsx(type, props, ...children) {
      const flat = children.flat(Infinity).filter(value => value !== undefined && value !== null && value !== false)
      return typeof type === "function"
        ? type({ ...props, children: flat.length === 1 ? flat[0] : flat })
        : { type, props: props ?? {}, children: flat }
    },
    __fragment: "Fragment",
    require: () => scripting
  }
  const run = code => {
    const module = { exports: {} }
    vm.runInNewContext(code, { ...context, module, exports: module.exports })
    return module.exports
  }
  return { runtime: run(runtimeCode), widget: fetch ? run(widgetCode) : null, presented, urls, storage }
}

function text(value) {
  if (value === null || value === undefined) return ""
  if (typeof value !== "object") return String(value)
  if (Array.isArray(value)) return value.map(text).join("")
  const children = value.children ?? []
  if (children.length === 1 && typeof children[0] === "function") return text(children[0]({ size: { width: 297, height: 123 } }))
  return text(children)
}

const traffic = { cn: 12, intl: 48 }
function mockAliyun(failSite) {
  return async (url, params) => {
    const site = params.AccessKeyId === overseas.accessKeyId ? "intl" : "cn"
    if (site === failSite) return { ok: false, status: 500, text: async () => "mock-down", json: async () => ({}) }
    return {
      ok: true, status: 200, text: async () => "",
      json: async () => params.Action === "ListCdtInternetTraffic"
        ? { TrafficDetails: [{ Traffic: traffic[site] * 1024 ** 3 }] }
        : { Instances: { Instance: [{ Status: "Running" }] } }
    }
  }
}

test("international accounts use the Singapore BSS endpoint; China-site accounts keep the default", () => {
  const { runtime } = load()
  assert.equal(runtime.bssEndpoint(overseas), "business.ap-southeast-1.aliyuncs.com")
  assert.equal(runtime.bssEndpoint(domestic), "business.aliyuncs.com")
  assert.equal(runtime.bssEndpoint({}), "business.aliyuncs.com")
})

test("a legacy single-account config is migrated as the first account and is not duplicated", () => {
  const legacy = { ...base, accessKeyId: "ak-cn", accessKeySecret: "sk-cn", ecsInstanceId: "i-cn" }
  const storage = new Map([["aliyun_cdt_monitor_config", JSON.stringify(legacy)]])
  const { runtime } = load(storage)
  const list = runtime.loadAccountProfiles(base)
  assert.equal(list.length, 1)
  assert.equal(list[0].id, "default")
  assert.equal(list[0].site, "cn")
  runtime.saveAccountProfiles(runtime.upsertAccountProfile(list, overseas))
  const next = runtime.loadAccountProfiles(base)
  assert.equal(next.map(item => item.id).join(","), "default,acct_intl")
})

test("widget parameter selects accounts by name, index, site keyword or all", () => {
  const { runtime } = load()
  const list = [domestic, overseas]
  const pick = (value, active) => runtime.selectWidgetAccounts(list, value, active)
  assert.equal(pick("").accounts[0].id, "acct_cn")
  assert.equal(pick("", "acct_intl").accounts[0].id, "acct_intl")
  assert.equal(pick("国外").accounts[0].id, "acct_intl")
  assert.equal(pick("2").accounts[0].id, "acct_intl")
  assert.equal(pick("海外").accounts[0].id, "acct_intl")
  assert.equal(pick(" 国内 ").accounts[0].id, "acct_cn")
  assert.equal(pick("全部").mode, "all")
  assert.equal(pick("ALL").accounts.length, 2)
  assert.equal(pick("不存在").accounts.length, 0)
  assert.equal(pick("不存在").unmatched, "不存在")
  assert.equal(runtime.selectWidgetAccounts([domestic], "全部").mode, "single")
})

test("per-account snapshot keys never collide and do not expose credentials", () => {
  const { runtime } = load()
  const a = runtime.scopedStorageKey("aliyun_cdt_widget_cache", domestic)
  const b = runtime.scopedStorageKey("aliyun_cdt_widget_cache", overseas)
  assert.notEqual(a, b)
  assert.equal(a.includes(domestic.accessKeyId), false)
  assert.equal(runtime.scopedStorageKey("k", { ...domestic, trafficThresholdGB: 500 }), runtime.scopedStorageKey("k", domestic))
})

test("the 'all' widget shows each account in its own panel and keeps a failing account visible", async () => {
  const storage = new Map([["aliyun_cdt_accounts_v1", JSON.stringify([domestic, overseas])]])
  const host = load(storage, { parameter: "全部", fetch: mockAliyun("intl") })
  await host.widget.main()
  const screen = text(host.presented[0])
  assert.match(screen, /国内/)
  assert.match(screen, /12\.00/)
  assert.match(screen, /国外/)
  assert.match(screen, /获取失败/)
  assert.ok(host.urls.every(url => !url.includes("business")), "widgets never call billing APIs")
  assert.ok([...storage.keys()].filter(key => key.startsWith("aliyun_cdt_widget_cache_")).length === 1)
})

test("a single-account widget fixed to the overseas account shows its own data and name", async () => {
  const storage = new Map([
    ["aliyun_cdt_accounts_v1", JSON.stringify([domestic, overseas])],
    ["aliyun_cdt_monitor_config", JSON.stringify(domestic)]
  ])
  const host = load(storage, { parameter: "国外", fetch: mockAliyun() })
  await host.widget.main()
  const screen = text(host.presented[0])
  assert.match(screen, /48\.00/)
  assert.match(screen, /国外/)
  assert.doesNotMatch(screen, /12\.00/)
  assert.ok(host.urls.some(url => url.includes("ecs.ap-southeast-1")))
})

test("an unknown widget parameter explains which account names are valid", async () => {
  const storage = new Map([["aliyun_cdt_accounts_v1", JSON.stringify([domestic, overseas])]])
  const host = load(storage, { parameter: "日本", fetch: mockAliyun() })
  await host.widget.main()
  const screen = text(host.presented[0])
  assert.match(screen, /未找到账号「日本」/)
  assert.match(screen, /国内、国外、全部/)
  assert.equal(host.urls.length, 0)
})
