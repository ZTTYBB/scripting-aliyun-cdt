/**
 * ============================================================================
 * 阿里云 CDT 流量监控与 ECS 状态看板【单文件通用版 (All-In-One)】
 * ============================================================================
 * 特性：
 * 1. 零硬编码凭据：所有人下载即可直接使用，首次打开自动弹出设置界面。
 * 2. 凭据存储在本机 Scripting Storage；本项目未实现应用层加密。
 * 3. 桌面小组件模式：自动根据尺寸呈现小号 / 中号 / 大号 / 锁屏组件。
 * 4. App 内控制台模式：呈现只读状态仪表盘与设置界面。
 * 5. 纯 TypeScript 内置 HMAC-SHA1 签名与 POP RPC 请求，零外部依赖。
 */

import {
  Widget,
  Navigation,
  Script,
  ScrollView,
  VStack,
  HStack,
  ZStack,
  Text,
  Image,
  ProgressView,
  Circle,
  RoundedRectangle,
  GeometryReader,
  Button,
  Spacer,
  Divider,
  NavigationStack,
  List,
  Section,
  useState,
  useEffect,
  useCallback
} from "scripting"

// BEGIN SHARED MONITOR RUNTIME: generated from monitor_runtime.ts
interface ConfigIdentityCfg {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  vpsCutoffReferenceGB: number
  resetDayOfMonth: number
}

interface DailyUsagePoint {
  date: string
  label: string
  valueGB: number | null
  isToday: boolean
}

interface MonitorSnapshot<T> {
  version: 2
  scope: string
  billingMonth: string
  sampledAt: number
  data: T
}

interface RuntimeTrafficSample {
  date: string
  totalGB: number
  updatedAt: number
}

interface RuntimeTrafficHistory {
  version: 2
  scope: string
  snapshots: RuntimeTrafficSample[]
}

const RUNTIME_SNAPSHOT_TTL_MS = 6 * 60 * 60 * 1000
const RUNTIME_LEGACY_HISTORY_KEY = "aliyun_cdt_daily_history_v1"
const RUNTIME_HISTORY_KEY = "aliyun_cdt_daily_history_v2_"

const RUNTIME_CHINA_OFFSET_MS = 8 * 60 * 60 * 1000
const RUNTIME_DAY_MS = 24 * 60 * 60 * 1000

interface ChinaDateParts {
  year: number
  month: number
  day: number
  weekday: number
}

// Aliyun billing cycles follow China Standard Time (UTC+8, no DST), regardless of the device time zone.
function chinaDateParts(date: Date): ChinaDateParts {
  const shifted = new Date(date.getTime() + RUNTIME_CHINA_OFFSET_MS)
  return {
    year: shifted.getUTCFullYear(),
    month: shifted.getUTCMonth() + 1,
    day: shifted.getUTCDate(),
    weekday: shifted.getUTCDay()
  }
}

function chinaMonthKey(date: Date, monthOffset = 0): string {
  const parts = chinaDateParts(date)
  const target = new Date(Date.UTC(parts.year, parts.month - 1 + monthOffset, 1))
  return `${target.getUTCFullYear()}-${String(target.getUTCMonth() + 1).padStart(2, "0")}`
}

function chinaMonthProgress(date: Date): {
  currentDay: number
  lastDay: number
  daysRemaining: number
  monthTimeProgress: number
} {
  const parts = chinaDateParts(date)
  const lastDay = new Date(Date.UTC(parts.year, parts.month, 0)).getUTCDate()
  return {
    currentDay: parts.day,
    lastDay,
    daysRemaining: Math.max(1, lastDay - parts.day + 1),
    monthTimeProgress: Math.min(100, Math.max(1, Number(((parts.day / lastDay) * 100).toFixed(1))))
  }
}

function usagePercentage(totalGB: number, thresholdGB: number): number {
  if (!Number.isFinite(totalGB) || !Number.isFinite(thresholdGB) || thresholdGB <= 0) return 0
  return Math.max(0, Number(((totalGB / thresholdGB) * 100).toFixed(1)))
}

type NormalizedEcsStatus = "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"

function normalizeEcsStatus(value: unknown): NormalizedEcsStatus {
  switch (String(value ?? "").trim().toLowerCase()) {
    case "running":
      return "Running"
    case "stopped":
      return "Stopped"
    case "starting":
      return "Starting"
    case "stopping":
      return "Stopping"
    default:
      return "Unknown"
  }
}

// Error bodies can echo the signed string (including the AccessKey ID); keep only the error code.
function aliyunHttpError(action: string, status: number, body: string): Error {
  let code = ""
  try {
    const parsed = JSON.parse(body)
    if (parsed && typeof parsed.Code === "string") code = parsed.Code
  } catch {
    const match = /<Code>([^<]{1,80})<\/Code>/.exec(body || "")
    if (match) code = match[1]
  }
  code = code.replace(/[^\w.\-]/g, "").slice(0, 80)
  return new Error(`Aliyun [${action}] 错误 (${status})${code ? `: ${code}` : ""}`)
}

function widgetErrorHint(message: unknown): string {
  const text = String(message ?? "")
  if (/InvalidAccessKeyId|SignatureDoesNotMatch|IncompleteSignature|InvalidAccessKeySecret/.test(text)) return "AccessKey 无效，请在 App 内检查凭据"
  if (/Forbidden|NoPermission|Unauthorized|\(403\)/.test(text)) return "RAM 权限不足，请在 App 内查看详情"
  if (/InvalidInstanceId|InvalidRegionId/.test(text)) return "实例或地域不匹配，请在 App 内检查"
  if (/timed out|Timeout|超时/i.test(text)) return "请求超时，稍后会自动重试"
  if (/Billing month changed/.test(text)) return "账期刚切换，稍后会自动刷新"
  return "网络异常或服务暂不可用"
}

function runtimeDateKey(date: Date): string {
  const parts = chinaDateParts(date)
  return `${parts.year}-${String(parts.month).padStart(2, "0")}-${String(parts.day).padStart(2, "0")}`
}

function runtimeOffsetDate(date: Date, offset: number): Date {
  return new Date(date.getTime() + offset * RUNTIME_DAY_MS)
}

function runtimeRecord(value: unknown): value is Record<string, any> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function runtimeTimestamp(value: unknown): number | null {
  if (value instanceof Date || Object.prototype.toString.call(value) === "[object Date]") {
    const time = (value as Date).getTime()
    return Number.isFinite(time) ? time : null
  }
  if (typeof value !== "number" && typeof value !== "string") return null
  if (typeof value === "string" && !value.trim()) return null
  const timestamp = new Date(value).getTime()
  return Number.isFinite(timestamp) ? timestamp : null
}

function runtimeParse(value: unknown): unknown {
  try {
    return typeof value === "string" ? JSON.parse(value) : value
  } catch {
    return null
  }
}

// A 128-bit non-cryptographic identifier; this is not encryption or authentication.
function runtimeFingerprint(source: string): string {
  let a = 1779033703
  let b = 3144134277
  let c = 1013904242
  let d = 2773480762
  for (let i = 0; i < source.length; i++) {
    const character = source.charCodeAt(i)
    a = b ^ Math.imul(a ^ character, 597399067)
    b = c ^ Math.imul(b ^ character, 2869860233)
    c = d ^ Math.imul(c ^ character, 951274213)
    d = a ^ Math.imul(d ^ character, 2716044179)
  }
  a = Math.imul(c ^ (a >>> 18), 597399067)
  b = Math.imul(d ^ (b >>> 22), 2869860233)
  c = Math.imul(a ^ (c >>> 17), 951274213)
  d = Math.imul(b ^ (d >>> 19), 2716044179)
  return [(a ^ b ^ c ^ d) >>> 0, (b ^ a) >>> 0, (c ^ a) >>> 0, (d ^ a) >>> 0]
    .map(value => value.toString(16).padStart(8, "0"))
    .join("")
}

function configScope(config: ConfigIdentityCfg): string {
  return runtimeFingerprint(JSON.stringify([
    config.accessKeyId.trim(),
    config.accessKeySecret.trim(),
    config.regionId.trim(),
    config.ecsInstanceId.trim(),
    config.trafficThresholdGB,
    config.vpsCutoffReferenceGB,
    config.resetDayOfMonth
  ]))
}

function accountHistoryScope(config: ConfigIdentityCfg): string {
  return runtimeFingerprint(JSON.stringify([config.accessKeyId.trim(), "cdt"]))
}

async function withRequestTimeout<T>(
  operation: (signal?: any) => Promise<T>,
  action: string,
  timeoutMs = 12000
): Promise<T> {
  const Controller = (globalThis as any).AbortController
  const controller = typeof Controller === "function" ? new Controller() : undefined
  const delay = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 12000
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Aliyun [${action}] request timed out (${delay} ms)`))
      try {
        controller?.abort()
      } catch {}
    }, delay)
  })
  try {
    // The operation includes body parsing, not just receiving HTTP headers.
    return await Promise.race([Promise.resolve().then(() => operation(controller?.signal)), deadline])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

function createSnapshot<T extends { totalGB: number; updatedAt?: unknown }>(
  config: ConfigIdentityCfg,
  data: T,
  now: Date = new Date()
): MonitorSnapshot<T> {
  const sampledAt = runtimeTimestamp(data.updatedAt)
  if (
    sampledAt === null || !Number.isFinite(now.getTime()) || sampledAt > now.getTime() ||
    !Number.isFinite(data.totalGB) || data.totalGB < 0
  ) {
    throw new Error("Cannot cache an invalid traffic sample")
  }
  return {
    version: 2,
    scope: configScope(config),
    billingMonth: runtimeDateKey(new Date(sampledAt)).slice(0, 7),
    sampledAt,
    data
  }
}

function readSnapshot<T = any>(
  raw: unknown,
  config: ConfigIdentityCfg,
  now: Date = new Date()
): T | null {
  const parsed = runtimeParse(raw)
  if (!runtimeRecord(parsed) || !runtimeRecord(parsed.data)) return null
  const time = now.getTime()
  const sampledAt = parsed.sampledAt
  const updatedAt = runtimeTimestamp(parsed.data.updatedAt)
  if (
    parsed.version !== 2 || parsed.scope !== configScope(config) ||
    typeof sampledAt !== "number" || !Number.isFinite(sampledAt) || !Number.isFinite(time) ||
    sampledAt > time || time - sampledAt > RUNTIME_SNAPSHOT_TTL_MS ||
    updatedAt !== sampledAt ||
    parsed.billingMonth !== runtimeDateKey(now).slice(0, 7) ||
    parsed.billingMonth !== runtimeDateKey(new Date(sampledAt)).slice(0, 7) ||
    typeof parsed.data.totalGB !== "number" || !Number.isFinite(parsed.data.totalGB) || parsed.data.totalGB < 0
  ) {
    return null
  }
  return { ...parsed.data, updatedAt: new Date(sampledAt) } as T
}

function createRefreshGate() {
  let generation = 0
  return {
    start(): number {
      return ++generation
    },
    invalidate(): void {
      generation++
    },
    isCurrent(token: number): boolean {
      return token === generation
    }
  }
}

function assertSampleBillingMonth(sampledAt: Date, now: Date = new Date()): void {
  if (
    !Number.isFinite(sampledAt.getTime()) || !Number.isFinite(now.getTime()) ||
    chinaMonthKey(sampledAt) !== chinaMonthKey(now)
  ) {
    throw new Error("Billing month changed; refresh required")
  }
}

function runtimeStorage(): any {
  return (globalThis as any).Storage
}

function runtimeLegacyScope(config: ConfigIdentityCfg): string {
  const source = `${config.accessKeyId.trim()}|cdt`
  let hash = 2166136261
  for (let i = 0; i < source.length; i++) {
    hash ^= source.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0).toString(36)
}

function runtimeValidSamples(samples: unknown, now: Date, includeLaterSamples: boolean): RuntimeTrafficSample[] {
  if (!Array.isArray(samples)) return []
  const earliest = runtimeDateKey(runtimeOffsetDate(now, -31))
  const today = runtimeDateKey(now)
  const byDate = new Map<string, RuntimeTrafficSample>()
  for (const item of samples) {
    if (
      !runtimeRecord(item) || typeof item.date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(item.date) ||
      item.date < earliest || (!includeLaterSamples && item.date > today) ||
      typeof item.totalGB !== "number" || !Number.isFinite(item.totalGB) || item.totalGB < 0 ||
      typeof item.updatedAt !== "number" || !Number.isFinite(item.updatedAt) ||
      (!includeLaterSamples && item.updatedAt > now.getTime()) ||
      runtimeDateKey(new Date(item.updatedAt)) !== item.date
    ) continue
    const prior = byDate.get(item.date)
    if (!prior || item.updatedAt > prior.updatedAt) {
      byDate.set(item.date, { date: item.date, totalGB: item.totalGB, updatedAt: item.updatedAt })
    }
  }
  return [...byDate.values()].sort((a, b) => a.date.localeCompare(b.date)).slice(-32)
}

function runtimeLoadHistory(
  config: ConfigIdentityCfg,
  now: Date,
  includeLaterSamples = false
): RuntimeTrafficHistory {
  const scope = accountHistoryScope(config)
  const empty: RuntimeTrafficHistory = { version: 2, scope, snapshots: [] }
  try {
    const storage = runtimeStorage()
    const raw = storage?.get?.(RUNTIME_HISTORY_KEY + scope)
    if (raw) {
      const parsed = runtimeParse(raw)
      if (!runtimeRecord(parsed) || parsed.version !== 2 || parsed.scope !== scope) return empty
      return { ...empty, snapshots: runtimeValidSamples(parsed.snapshots, now, includeLaterSamples) }
    }
    const legacy = runtimeParse(storage?.get?.(RUNTIME_LEGACY_HISTORY_KEY))
    if (
      runtimeRecord(legacy) && legacy.version === 1 && legacy.scope === runtimeLegacyScope(config) &&
      typeof legacy.month === "string" && /^\d{4}-\d{2}$/.test(legacy.month) && Array.isArray(legacy.snapshots)
    ) {
      const snapshots = runtimeValidSamples(
        legacy.snapshots.filter(item => runtimeRecord(item) && typeof item.date === "string" && item.date.slice(0, 7) === legacy.month),
        now,
        includeLaterSamples
      )
      return { ...empty, snapshots }
    }
  } catch {}
  return empty
}

function runtimeBuildDailyUsage(snapshots: RuntimeTrafficSample[], now: Date): DailyUsagePoint[] {
  const byDate = new Map(snapshots.map(item => [item.date, item]))
  const weekdayLabels = ["\u65e5", "\u4e00", "\u4e8c", "\u4e09", "\u56db", "\u4e94", "\u516d"]
  return Array.from({ length: 7 }, (_, index) => {
    const date = runtimeOffsetDate(now, index - 6)
    const key = runtimeDateKey(date)
    const previousKey = runtimeDateKey(runtimeOffsetDate(date, -1))
    const current = byDate.get(key)
    const previous = byDate.get(previousKey)
    let valueGB: number | null = null
    if (
      current && previous && key.slice(0, 7) === previousKey.slice(0, 7) &&
      current.updatedAt > previous.updatedAt && current.totalGB + 0.005 >= previous.totalGB
    ) {
      valueGB = Math.max(0, Number((current.totalGB - previous.totalGB).toFixed(2)))
    }
    return { date: key, label: index === 6 ? "\u4eca" : weekdayLabels[chinaDateParts(date).weekday], valueGB, isToday: index === 6 }
  })
}

function recordTrafficSample(
  config: ConfigIdentityCfg,
  totalGB: number,
  now: Date = new Date()
): DailyUsagePoint[] {
  const history = runtimeLoadHistory(config, now, true)
  const updatedAt = now.getTime()
  const latest = history.snapshots[history.snapshots.length - 1]
  if (
    !Number.isFinite(updatedAt) || !Number.isFinite(totalGB) || totalGB < 0 ||
    (latest && latest.updatedAt >= updatedAt)
  ) {
    return runtimeBuildDailyUsage(runtimeValidSamples(history.snapshots, now, false), now)
  }
  const date = runtimeDateKey(now)
  const month = date.slice(0, 7)
  // Only discard the current billing month's baseline when its counter decreases.
  if (latest?.date.slice(0, 7) === month && totalGB + 0.005 < latest.totalGB) {
    history.snapshots = history.snapshots.filter(item => item.date.slice(0, 7) !== month)
  }
  history.snapshots = history.snapshots.filter(item => item.date !== date)
  history.snapshots.push({ date, totalGB, updatedAt })
  history.snapshots = runtimeValidSamples(history.snapshots, now, false)
  try {
    runtimeStorage()?.set?.(RUNTIME_HISTORY_KEY + history.scope, JSON.stringify(history))
  } catch {}
  return runtimeBuildDailyUsage(history.snapshots, now)
}

function readDailyUsage(config: ConfigIdentityCfg, now: Date = new Date()): DailyUsagePoint[] {
  return runtimeBuildDailyUsage(runtimeLoadHistory(config, now).snapshots, now)
}

function sumCompleteSevenDays(points: DailyUsagePoint[]): number | null {
  if (points.length !== 7 || points.some(point => point.valueGB === null || !Number.isFinite(point.valueGB) || point.valueGB < 0)) {
    return null
  }
  return Number(points.reduce((sum, point) => sum + point.valueGB!, 0).toFixed(2))
}

// ==================== Multi-account profiles ====================

interface AccountProfileFields {
  id?: string
  name?: string
  site?: string
}

const RUNTIME_ACCOUNTS_KEY = "aliyun_cdt_accounts_v1"
const RUNTIME_ACTIVE_CONFIG_KEY = "aliyun_cdt_monitor_config"
const RUNTIME_ALL_ACCOUNTS_WORDS = ["全部", "所有", "汇总", "all", "*"]
const RUNTIME_INTL_WORDS = ["国际", "国际站", "国外", "海外", "intl", "international"]
const RUNTIME_CN_WORDS = ["国内", "中国", "中国站", "cn", "china"]

/** 国际站账号的 BSS 账单接口必须走新加坡入口，否则会报账号不存在。 */
function bssEndpoint(config: AccountProfileFields): string {
  return config.site === "intl" ? "business.ap-southeast-1.aliyuncs.com" : "business.aliyuncs.com"
}

function siteLabel(site: unknown): string {
  return site === "intl" ? "国际站" : "中国站"
}

function accountDisplayName(config: AccountProfileFields, index = 0): string {
  const name = typeof config.name === "string" ? config.name.trim() : ""
  if (name) return name
  if (config.site === "intl") return "国际站"
  return index > 0 ? `账号 ${index + 1}` : "中国站"
}

/** 按账号区分快照存储键；不含阈值，修改参考值不会丢缓存。 */
function accountStorageId(config: ConfigIdentityCfg): string {
  return runtimeFingerprint(JSON.stringify([
    config.accessKeyId.trim(), config.regionId.trim(), config.ecsInstanceId.trim(), "account"
  ]))
}

function scopedStorageKey(base: string, config: ConfigIdentityCfg): string {
  return `${base}_${accountStorageId(config)}`
}

function newAccountId(now: number = Date.now()): string {
  return `acct_${now.toString(36)}${Math.floor(Math.random() * 1679616).toString(36)}`
}

function runtimeAccountReady(value: unknown): value is Record<string, any> {
  return runtimeRecord(value) &&
    typeof value.accessKeyId === "string" && value.accessKeyId.trim() !== "" &&
    typeof value.accessKeySecret === "string" && value.accessKeySecret.trim() !== "" &&
    typeof value.ecsInstanceId === "string" && value.ecsInstanceId.trim() !== ""
}

/** 读取账号列表；旧版只有单账号配置时自动把它当作第一个账号。 */
function loadAccountProfiles<T extends ConfigIdentityCfg & AccountProfileFields>(defaults: T): T[] {
  const storage = runtimeStorage()
  const list: T[] = []
  const normalize = (value: Record<string, any>, fallbackId: string): T => {
    const item = { ...defaults, ...value } as T
    item.id = typeof item.id === "string" && item.id.trim() ? item.id.trim() : fallbackId
    item.site = item.site === "intl" ? "intl" : "cn"
    return item
  }
  try {
    const parsed = runtimeParse(storage?.get?.(RUNTIME_ACCOUNTS_KEY))
    if (Array.isArray(parsed)) {
      parsed.forEach((value, index) => {
        if (!runtimeAccountReady(value)) return
        const item = normalize(value, `acct_${index}`)
        if (!list.some(existing => existing.id === item.id)) list.push(item)
      })
    }
  } catch {}
  try {
    const active = runtimeParse(storage?.get?.(RUNTIME_ACTIVE_CONFIG_KEY))
    if (runtimeAccountReady(active)) {
      const item = normalize(active, "default")
      const known = list.some(existing =>
        existing.id === item.id || accountStorageId(existing) === accountStorageId(item))
      if (!known) list.push(item)
    }
  } catch {}
  return list
}

function saveAccountProfiles(list: Array<ConfigIdentityCfg & AccountProfileFields>): void {
  try {
    runtimeStorage()?.set?.(RUNTIME_ACCOUNTS_KEY, JSON.stringify(list))
  } catch {}
}

function upsertAccountProfile<T extends AccountProfileFields>(list: T[], profile: T): T[] {
  const index = list.findIndex(item => item.id === profile.id)
  if (index < 0) return [...list, profile]
  const next = list.slice()
  next[index] = profile
  return next
}

function removeAccountProfile<T extends AccountProfileFields>(list: T[], id: string | undefined): T[] {
  return list.filter(item => item.id !== id)
}

interface WidgetAccountSelection<T> {
  mode: "single" | "all"
  accounts: T[]
  unmatched?: string
}

/** 解析小组件 Parameter：留空=App 当前账号，名称/序号/国内/国外=单账号，全部=汇总。 */
function selectWidgetAccounts<T extends AccountProfileFields>(
  list: T[],
  parameter: unknown,
  activeId?: string
): WidgetAccountSelection<T> {
  const raw = typeof parameter === "string" ? parameter.trim() : ""
  const key = raw.toLowerCase()
  if (list.length === 0) return { mode: "single", accounts: [] }
  if (!key) return { mode: "single", accounts: [list.find(item => item.id === activeId) ?? list[0]] }
  if (RUNTIME_ALL_ACCOUNTS_WORDS.includes(key)) {
    return list.length > 1 ? { mode: "all", accounts: list } : { mode: "single", accounts: [list[0]] }
  }
  const names = list.map((item, index) => accountDisplayName(item, index).toLowerCase())
  const exact = names.indexOf(key)
  if (exact >= 0) return { mode: "single", accounts: [list[exact]] }
  if (/^\d+$/.test(key)) {
    const position = Number(key)
    if (position >= 1 && position <= list.length) return { mode: "single", accounts: [list[position - 1]] }
  }
  if (RUNTIME_INTL_WORDS.includes(key)) {
    const match = list.find(item => item.site === "intl")
    if (match) return { mode: "single", accounts: [match] }
  }
  if (RUNTIME_CN_WORDS.includes(key)) {
    const match = list.find(item => item.site !== "intl")
    if (match) return { mode: "single", accounts: [match] }
  }
  const partial = names.findIndex(name => name.includes(key))
  if (partial >= 0) return { mode: "single", accounts: [list[partial]] }
  return { mode: "single", accounts: [], unmatched: raw }
}
// END SHARED MONITOR RUNTIME

// BEGIN SHARED BILL QUERIES: generated from bill_queries.ts
type BillQueryParams = Record<string, string | number | boolean>

interface AccountBillQueryResult {
  available: boolean
  items: any[]
}

interface AccountBillQueryOptions {
  pageSize?: number
  maxPages?: number
  timeoutMs?: number
}

function isBillQueryAvailable(response: any): boolean {
  return response !== null
    && typeof response === "object"
    && response.Success !== false
    && (response.Code === undefined || response.Code === "Success")
    && Array.isArray(response.Data?.Items?.Item)
}

function pageInteger(value: unknown): number | undefined {
  if (typeof value !== "number" && typeof value !== "string") return undefined
  if (typeof value === "string" && !/^\d+$/.test(value.trim())) return undefined
  const parsed = Number(value)
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : undefined
}

function stableRecord(value: any): any {
  if (Array.isArray(value)) return value.map(stableRecord)
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value).sort().map(key => [key, stableRecord(value[key])])
    )
  }
  return value
}

async function queryAccountBillPages(
  request: (params: BillQueryParams) => Promise<any>,
  params: BillQueryParams,
  options: AccountBillQueryOptions = {}
): Promise<AccountBillQueryResult> {
  const unavailable = (): AccountBillQueryResult => ({ available: false, items: [] })
  const pageSize = options.pageSize ?? pageInteger(params.PageSize) ?? 300
  const maxPages = options.maxPages ?? 100
  const timeoutMs = options.timeoutMs ?? 12000
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 300
    || !Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 100
    || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return unavailable()
  }

  let expired = false
  const deadline = Date.now() + timeoutMs
  const collect = async (): Promise<AccountBillQueryResult> => {
    const items: any[] = []
    const seenPages = new Set<string>()
    let totalCount: number | undefined
    for (let pageNum = 1; pageNum <= maxPages; pageNum++) {
      if (expired || Date.now() >= deadline) return unavailable()
      const response = await request({ ...params, PageSize: pageSize, PageNum: pageNum })
      if (expired || Date.now() >= deadline || !isBillQueryAvailable(response)) {
        return unavailable()
      }
      const pageItems = response.Data.Items.Item as any[]
      if (pageItems.length > pageSize) return unavailable()
      const rawPageNum = response.Data.PageNum
      if (rawPageNum !== undefined && pageInteger(rawPageNum) !== pageNum) {
        return unavailable()
      }
      const rawPageSize = response.Data.PageSize
      if (rawPageSize !== undefined && pageInteger(rawPageSize) !== pageSize) {
        return unavailable()
      }
      const rawTotal = response.Data.TotalCount !== undefined
        ? response.Data.TotalCount
        : response.TotalCount
      if (rawTotal !== undefined) {
        const reportedTotal = pageInteger(rawTotal)
        if (reportedTotal === undefined
          || reportedTotal > pageSize * maxPages
          || (totalCount !== undefined && totalCount !== reportedTotal)) {
          return unavailable()
        }
        totalCount = reportedTotal
      }
      if (pageItems.length > 0) {
        const fingerprint = JSON.stringify(pageItems.map(item => JSON.stringify(stableRecord(item))).sort())
        if (seenPages.has(fingerprint)) return unavailable()
        seenPages.add(fingerprint)
        items.push(...pageItems)
      }

      if (totalCount !== undefined) {
        if (items.length > totalCount) return unavailable()
        if (items.length === totalCount) return { available: true, items }
        if (pageItems.length === 0) return unavailable()
      } else if (pageItems.length < pageSize) {
        return { available: true, items }
      }
    }
    return unavailable()
  }

  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      collect().catch(unavailable),
      new Promise<AccountBillQueryResult>(resolve => {
        timer = setTimeout(() => {
          expired = true
          resolve(unavailable())
        }, timeoutMs)
      })
    ])
  } finally {
    if (timer !== undefined) clearTimeout(timer)
  }
}

interface RecentBillingDate {
  dateStr: string
  displayDate: string
  isToday: boolean
  billingCycle: string
}

function recentBillingDates(now: Date, count: number = 7): RecentBillingDate[] {
  if (!Number.isFinite(now.getTime()) || !Number.isSafeInteger(count) || count < 1) return []
  return Array.from({ length: count }, (_, index) => {
    // Billing dates follow China Standard Time (UTC+8, no DST).
    const date = new Date(now.getTime() + 8 * 60 * 60 * 1000 - index * 24 * 60 * 60 * 1000)
    const year = String(date.getUTCFullYear()).padStart(4, "0")
    const month = String(date.getUTCMonth() + 1).padStart(2, "0")
    const day = String(date.getUTCDate()).padStart(2, "0")
    return {
      dateStr: `${year}-${month}-${day}`,
      displayDate: `${month}-${day}`,
      isToday: index === 0,
      billingCycle: `${year}-${month}`
    }
  })
}
// END SHARED BILL QUERIES

// ==================== 1. 本地存储配置管理 ====================

const APP_VERSION = "1.6.5"

interface AppConfig {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  vpsCutoffReferenceGB: number
  resetDayOfMonth: number
  /** 多账号：本机账号标识、显示名称、站点（cn=中国站，intl=国际站） */
  id?: string
  name?: string
  site?: string
}

const STORAGE_KEY = "aliyun_cdt_monitor_config"

const DEFAULT_CONFIG: AppConfig = {
  accessKeyId: "",
  accessKeySecret: "",
  regionId: "cn-hongkong",
  ecsInstanceId: "",
  trafficThresholdGB: 200,
  vpsCutoffReferenceGB: 195,
  resetDayOfMonth: 1
}

function loadSavedConfig(): AppConfig {
  try {
    if (typeof Storage !== "undefined" && Storage?.get) {
      const saved = Storage.get(STORAGE_KEY)
      if (saved) {
        const parsed = typeof saved === "string" ? JSON.parse(saved) : saved
        const cfg: AppConfig = { ...DEFAULT_CONFIG, ...parsed }
        // 旧版单账号配置没有 id，与 loadAccountProfiles 的迁移规则保持一致。
        if (!cfg.id) cfg.id = "default"
        cfg.site = cfg.site === "intl" ? "intl" : "cn"
        return cfg
      }
    }
  } catch (e) {
    console.error("加载配置失败:", e)
  }
  return { ...DEFAULT_CONFIG }
}

function saveConfigToStorage(cfg: AppConfig): void {
  try {
    if (typeof Storage !== "undefined" && Storage?.set) {
      // 先读出旧列表（含尚未迁移的旧版单账号），再写入当前账号，避免添加新账号时丢掉旧账号。
      if (cfg.id) saveAccountProfiles(upsertAccountProfile(loadAccountProfiles<AppConfig>(DEFAULT_CONFIG), cfg))
      Storage.set(STORAGE_KEY, JSON.stringify(cfg))
    }
  } catch (e) {
    console.error("保存配置失败:", e)
  }
}

function isConfigReady(cfg: AppConfig): boolean {
  return (
    Boolean(cfg.accessKeyId?.trim()) &&
    Boolean(cfg.accessKeySecret?.trim()) &&
    Boolean(cfg.ecsInstanceId?.trim())
  )
}

// ==================== 2. 纯 TS HMAC-SHA1 与 POP 签名引擎 ====================

function safeAdd(x: number, y: number): number {
  const lsw = (x & 0xffff) + (y & 0xffff)
  const msw = (x >> 16) + (y >> 16) + (lsw >> 16)
  return (msw << 16) | (lsw & 0xffff)
}

function rol(num: number, cnt: number): number {
  return (num << cnt) | (num >>> (32 - cnt))
}

function sha1Core(x: number[], len: number): number[] {
  x[len >> 5] |= 0x80 << (24 - (len % 32))
  x[(((len + 64) >> 9) << 4) + 15] = len

  const w: number[] = new Array(80)
  let a = 1732584193
  let b = -271733879
  let c = -1732584194
  let d = 271733878
  let e = -1009589776

  for (let i = 0; i < x.length; i += 16) {
    const olda = a
    const oldb = b
    const oldc = c
    const oldd = d
    const olde = e

    for (let j = 0; j < 80; j++) {
      if (j < 16) {
        w[j] = x[i + j] || 0
      } else {
        w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1)
      }
      let t: number
      if (j < 20) {
        t = safeAdd(safeAdd(rol(a, 5), (b & c) | (~b & d)), safeAdd(safeAdd(e, w[j]), 1518500249))
      } else if (j < 40) {
        t = safeAdd(safeAdd(rol(a, 5), b ^ c ^ d), safeAdd(safeAdd(e, w[j]), 1859775393))
      } else if (j < 60) {
        t = safeAdd(safeAdd(rol(a, 5), (b & c) | (b & d) | (c & d)), safeAdd(safeAdd(e, w[j]), -1894007588))
      } else {
        t = safeAdd(safeAdd(rol(a, 5), b ^ c ^ d), safeAdd(safeAdd(e, w[j]), -899497514))
      }
      e = d
      d = c
      c = rol(b, 30)
      b = a
      a = t
    }

    a = safeAdd(a, olda)
    b = safeAdd(b, oldb)
    c = safeAdd(c, oldc)
    d = safeAdd(d, oldd)
    e = safeAdd(e, olde)
  }
  return [a, b, c, d, e]
}

function str2binb(str: string): number[] {
  const bin: number[] = []
  const mask = (1 << 8) - 1
  for (let i = 0; i < str.length * 8; i += 8) {
    bin[i >> 5] |= (str.charCodeAt(i / 8) & mask) << (24 - (i % 32))
  }
  return bin
}

function binb2b64(binarray: number[]): string {
  const tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  let str = ""
  for (let i = 0; i < binarray.length * 4; i += 3) {
    const triplet =
      (((binarray[i >> 2] >> (8 * (3 - (i % 4)))) & 0xff) << 16) |
      (((binarray[(i + 1) >> 2] >> (8 * (3 - ((i + 1) % 4)))) & 0xff) << 8) |
      ((binarray[(i + 2) >> 2] >> (8 * (3 - ((i + 2) % 4)))) & 0xff)
    for (let j = 0; j < 4; j++) {
      if (i * 8 + j * 6 > binarray.length * 32) {
        str += "="
      } else {
        str += tab.charAt((triplet >> (6 * (3 - j))) & 0x3f)
      }
    }
  }
  return str
}

function hmacSha1Base64(key: string, data: string): string {
  let bkey = str2binb(key)
  if (bkey.length > 16) {
    bkey = sha1Core(bkey, key.length * 8)
  }
  const ipad: number[] = new Array(16)
  const opad: number[] = new Array(16)
  for (let i = 0; i < 16; i++) {
    ipad[i] = (bkey[i] || 0) ^ 0x36363636
    opad[i] = (bkey[i] || 0) ^ 0x5c5c5c5c
  }
  const hash = sha1Core(ipad.concat(str2binb(data)), 512 + data.length * 8)
  return binb2b64(sha1Core(opad.concat(hash), 512 + 160))
}

function percentEncode(str: string): string {
  return encodeURIComponent(str)
    .replace(/!/g, "%21")
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A")
}

async function aliyunRequest<T = any>(
  domain: string,
  action: string,
  version: string,
  config: AppConfig,
  params: Record<string, string | number | boolean> = {}
): Promise<T> {
  const method = "POST"
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z")
  const nonce = Date.now().toString(36) + Math.random().toString(36).substring(2)

  const allParams: Record<string, string> = {
    Format: "JSON",
    Version: version,
    AccessKeyId: config.accessKeyId.trim(),
    SignatureMethod: "HMAC-SHA1",
    Timestamp: timestamp,
    SignatureVersion: "1.0",
    SignatureNonce: nonce,
    Action: action,
    ...Object.fromEntries(Object.entries(params).map(([k, v]) => [k, String(v)]))
  }

  const sortedKeys = Object.keys(allParams).sort()
  const canonicalizedQueryString = sortedKeys
    .map(k => `${percentEncode(k)}=${percentEncode(allParams[k])}`)
    .join("&")

  const stringToSign = `${method}&${percentEncode("/")}&${percentEncode(canonicalizedQueryString)}`
  const signature = hmacSha1Base64(config.accessKeySecret.trim() + "&", stringToSign)

  const requestUrl = `https://${domain}/`
  const bodyString = `${canonicalizedQueryString}&Signature=${percentEncode(signature)}`

  return withRequestTimeout(async signal => {
    const response = await fetch(requestUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: bodyString,
      ...(signal ? { signal } : {})
    })
    if (!response.ok) {
      throw aliyunHttpError(action, response.status, await response.text())
    }
    return (await response.json()) as T
  }, action)
}

// ==================== 3. 业务数据模型 ====================

export interface AccountBalanceInfo {
  availableAmount: string
  availableCashAmount: string
  currency: string
  status: "sufficient" | "low" | "arrears"
}

export interface DailyExpenseItem {
  date: string
  amount: string
  isToday?: boolean
  settled?: boolean
  available?: boolean
}

export interface MonthlyBillInfo {
  billingCycle: string
  paymentAmount: string
  hasRecords?: boolean
  // Optional so snapshots saved before this metadata was introduced still render safely.
  paymentScope?: "monitoredProducts" | "allProducts"
  outstandingAmount: string
  currency: string
  ecsAmount: string
  eipAmount: string
  cdtAmount: string
  ecsDailyList: DailyExpenseItem[]
  eipDailyList: DailyExpenseItem[]
}

function getMonthlyBillPresentation(bill?: MonthlyBillInfo | null): { label: string; detail: string } {
  if (bill?.paymentScope === "allProducts") {
    return {
      label: "本月全部产品费用",
      detail: "当前全部产品账单查询结果（可能延迟）"
    }
  }

  if (bill?.paymentScope === "monitoredProducts") {
    return {
      label: "本月监控产品费用",
      detail: "仅含已识别的监控产品，不含其他阿里云产品（可能延迟）"
    }
  }

  return {
    label: "本月监控产品费用",
    detail: "费用范围未标记，按监控产品费用显示；可能不含其他阿里云产品（请刷新确认）"
  }
}

interface MonitorData {
  totalGB: number
  thresholdGB: number
  vpsCutoffReferenceGB: number
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  monthTimeProgress: number
  dailyUsage: DailyUsagePoint[]
  sevenDayTotalGB: number | null
  todayEstimatedGB: number | null
  updatedAt: Date
  isCached?: boolean
  ecsStatus: "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"
  publicIp?: string
  color: string
  financialBalance?: AccountBalanceInfo | null
  financialBill?: MonthlyBillInfo | null
  financialBillStatus: "available" | "unavailable"
  accountName?: string
}

const SNAPSHOT_STORAGE_KEY = "aliyun_cdt_dashboard_cache"
const WIDGET_SNAPSHOT_STORAGE_KEY = "aliyun_cdt_widget_cache"
const PRIVACY_STORAGE_KEY = "aliyun_cdt_privacy_mode"

type ECSIpValue = string | string[] | undefined

interface ECSInstanceRecord {
  Status: string
  PublicIpAddress?: { IpAddress?: ECSIpValue }
  EipAddress?: { IpAddress?: ECSIpValue }
  PublicIpAddresses?: ECSIpValue
  EipAddresses?: ECSIpValue
}

function firstIp(value: unknown): string | undefined {
  if (Array.isArray(value)) {
    return value.find(item => typeof item === "string" && item.trim().length > 0)?.trim()
  }
  if (typeof value !== "string") return undefined
  const text = value.trim()
  if (!text) return undefined
  if (text.startsWith("[")) {
    try {
      return firstIp(JSON.parse(text))
    } catch {
      return undefined
    }
  }
  return text
}

function getInstancePublicIp(instance?: ECSInstanceRecord): string | undefined {
  // 绑定弹性公网 IP 时，DescribeInstances 将地址放在 EipAddress，而不是 PublicIpAddress。
  return firstIp(instance?.EipAddress?.IpAddress)
    || firstIp(instance?.PublicIpAddress?.IpAddress)
    || firstIp(instance?.EipAddresses)
    || firstIp(instance?.PublicIpAddresses)
}

async function queryBillItemsForCycle(config: AppConfig, billingCycle: string): Promise<{ available: boolean; items: any[] }> {
  const overview = await aliyunRequest(
    bssEndpoint(config), "QueryBillOverview", "2017-12-14", config, { BillingCycle: billingCycle }
  ).catch(() => null)
  if (isBillQueryAvailable(overview) && overview.Data.Items.Item.length > 0) {
    return { available: true, items: overview.Data.Items.Item }
  }
  return queryAccountBillPages(
    params => aliyunRequest(bssEndpoint(config), "QueryAccountBill", "2017-12-14", config, params),
    { BillingCycle: billingCycle, IsGroupByProduct: true }
  )
}

async function fetchMonitorData(config: AppConfig, includeFinancial: boolean = true): Promise<MonitorData> {
  const now = new Date()
  const [cdtData, ecsData] = await Promise.all([
    aliyunRequest<{ TrafficDetails?: Array<{ Traffic?: number }> }>(
      "cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config
    ),
    aliyunRequest<{ Instances?: { Instance?: ECSInstanceRecord[] } }>(
      `ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
        InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
        RegionId: config.regionId.trim()
      }
    ).catch(() => null)
  ])
  assertSampleBillingMonth(now)

  const details = cdtData.TrafficDetails || []
  const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB > 0 ? config.trafficThresholdGB : DEFAULT_CONFIG.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB > 0 ? config.vpsCutoffReferenceGB : DEFAULT_CONFIG.vpsCutoffReferenceGB
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = usagePercentage(totalGB, thresholdGB)

  // 查询 ECS 状态；失败时仍保留已成功获取的 CDT 用量。
  const instance = ecsData?.Instances?.Instance?.[0]
  const ecsStatus: MonitorData["ecsStatus"] = normalizeEcsStatus(instance?.Status)
  const publicIp = getInstancePublicIp(instance)

  // 纯统计模式：手机端仅只读拉取用量与账单，关机熔断由 VPS 独立守护

  const { daysRemaining, monthTimeProgress } = chinaMonthProgress(now)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(2)
  // Sampling is committed only after the caller accepts its request generation.
  const dailyUsage = readDailyUsage(config, now)
  const sevenDayTotalGB = sumCompleteSevenDays(dailyUsage)
  const todayEstimatedGB = dailyUsage[dailyUsage.length - 1]?.valueGB ?? null

  // 5. 资产与消费查询 (优雅降级，未授权时不中断主流程)
  let financialBalance: AccountBalanceInfo | null = null
  let financialBill: MonthlyBillInfo | null = null
  let financialBillStatus: "available" | "unavailable" = "unavailable"

  if (includeFinancial) {
  try {
    const balRes = await aliyunRequest<{
      Data?: {
        AvailableAmount?: string
        AvailableCashAmount?: string
        CreditAmount?: string
        Currency?: string
      }
    }>(bssEndpoint(config), "QueryAccountBalance", "2017-12-14", config).catch(() => null)

    if (balRes?.Data) {
      const cash = parseFloat(balRes.Data.AvailableCashAmount || "0")
      const availableAmount = parseFloat(balRes.Data.AvailableAmount || "")
      let status: "sufficient" | "low" | "arrears" = "sufficient"
      if (Number.isFinite(availableAmount) && availableAmount < 0) {
        status = "arrears"
      } else if (cash < 10) {
        status = "low"
      }
      financialBalance = {
        availableAmount: balRes.Data.AvailableAmount || "0.00",
        availableCashAmount: balRes.Data.AvailableCashAmount || "0.00",
        currency: balRes.Data.Currency || "CNY",
        status
      }
    }
  } catch {}

  try {
    const cycle = chinaMonthKey(now)

    const monthResult = await queryBillItemsForCycle(config, cycle)
    const billItems = monthResult.items
    financialBillStatus = monthResult.available ? "available" : "unavailable"

    if (financialBillStatus === "available") {
      let allProductsEffective = 0
      let ecsTotal = 0
      let eipTotal = 0
      let cdtTotal = 0
      let hasInfrastructureItems = false
      let outstanding = 0
      let currency = "CNY"

      for (const it of billItems) {
        const code = String(it.PipCode || it.ProductCode || "").toLowerCase()
        const name = String(it.ProductName || "")
        const pay = Number(it.PaymentAmount || 0)
        const gross = Number(it.PretaxGrossAmount || 0)
        // A present PretaxAmount is authoritative, including an explicit zero.
        const hasPretaxAmount = it.PretaxAmount !== undefined && it.PretaxAmount !== null && it.PretaxAmount !== ""
        let effective = 0
        if (hasPretaxAmount) {
          effective = Number(it.PretaxAmount) || 0
        } else if (it.PaymentAmount !== undefined && it.PaymentAmount !== null && it.PaymentAmount !== "") {
          effective = Number(it.PaymentAmount) || 0
        } else {
          effective = gross
        }

        allProductsEffective += effective
        outstanding += Number(it.OutstandingAmount || 0)
        if (it.Currency) currency = it.Currency

        const isEcs = code === "ecs" || code.includes("ecs") || name.includes("云服务器") || name.includes("ECS")
        const isEip = code === "eip" || code === "cbwp" || code.includes("eip") || code.includes("cbwp") || name.includes("弹性公网") || name.includes("EIP") || name.includes("公网IP") || name.includes("共享带宽")
        const isCdt = code === "cdt" || code.includes("cdt") || name.includes("云数据传输") || name.includes("CDT")
        if (isEcs || isEip || isCdt) hasInfrastructureItems = true

        if (isEcs) {
          ecsTotal += effective
        } else if (isEip) {
          eipTotal += effective
        } else if (isCdt) {
          cdtTotal += effective
        }
      }

      // Keep recognized infrastructure zeros authoritative; fall back only when no such rows exist.
      const infrastructureTotal = ecsTotal + eipTotal + cdtTotal
      const finalPayment = hasInfrastructureItems
        ? infrastructureTotal
        : allProductsEffective

      const formatDaily = (amt: number): string => {
        if (amt <= 0) return "0.00"
        if (amt < 0.01) return amt.toFixed(3)
        return amt.toFixed(2)
      }

      // QueryAccountBill returns daily product-category totals that may lag and are provisional for the current month.
      const ecsDailyList: DailyExpenseItem[] = []
      const eipDailyList: DailyExpenseItem[] = []
      const dateQueries = recentBillingDates(now)

      try {
        const dailyResults = await Promise.all(
          dateQueries.map(async q => {
            try {
              const dayResult = await queryAccountBillPages(
                params => aliyunRequest(bssEndpoint(config), "QueryAccountBill", "2017-12-14", config, params),
                {
                  BillingCycle: q.billingCycle,
                  Granularity: "DAILY",
                  BillingDate: q.dateStr,
                  IsGroupByProduct: true
                }
              )
              const dayItems = dayResult.items
              let dEcs = 0
              let dEip = 0
              for (const it of dayItems) {
                const c = String(it.PipCode || it.ProductCode || "").toLowerCase()
                const n = String(it.ProductName || "")
                const p = Number(it.PaymentAmount || 0)
                const g = Number(it.PretaxGrossAmount || 0)
                // A present PretaxAmount is authoritative, including an explicit zero.
                let eff = 0
                if (it.PretaxAmount !== undefined && it.PretaxAmount !== null && it.PretaxAmount !== "") {
                  eff = Number(it.PretaxAmount) || 0
                } else if (it.PaymentAmount !== undefined && it.PaymentAmount !== null && it.PaymentAmount !== "") {
                  eff = p
                } else {
                  eff = g
                }

                if (c === "ecs" || c.includes("ecs") || n.includes("云服务器") || n.includes("ECS")) {
                  dEcs += eff
                } else if (
                  c === "eip" ||
                  c === "cbwp" ||
                  c.includes("eip") ||
                  c.includes("cbwp") ||
                  n.includes("弹性公网") ||
                  n.includes("EIP") ||
                  n.includes("公网IP") ||
                  n.includes("共享带宽")
                ) {
                  dEip += eff
                }
              }
              return {
                date: q.displayDate,
                isToday: q.isToday,
                ecsAmount: formatDaily(dEcs),
                eipAmount: formatDaily(dEip),
                settled: dayItems.length > 0,
                available: dayResult.available
              }
            } catch {
              return {
                date: q.displayDate,
                isToday: q.isToday,
                ecsAmount: "0.00",
                eipAmount: "0.00",
                settled: false,
                available: false
              }
            }
          })
        )

        for (const r of dailyResults) {
          ecsDailyList.push({ date: r.date, amount: r.ecsAmount, isToday: r.isToday, settled: r.settled, available: r.available })
          eipDailyList.push({ date: r.date, amount: r.eipAmount, isToday: r.isToday, settled: r.settled, available: r.available })
        }
      } catch {
        for (const q of dateQueries) {
          ecsDailyList.push({ date: q.displayDate, amount: "0.00", isToday: q.isToday, settled: false, available: false })
          eipDailyList.push({ date: q.displayDate, amount: "0.00", isToday: q.isToday, settled: false, available: false })
        }
      }

      financialBill = {
        billingCycle: cycle,
        paymentAmount: finalPayment.toFixed(2),
        hasRecords: billItems.length > 0,
        paymentScope: hasInfrastructureItems ? "monitoredProducts" : "allProducts",
        outstandingAmount: outstanding.toFixed(2),
        currency,
        ecsAmount: ecsTotal.toFixed(2),
        eipAmount: eipTotal.toFixed(2),
        cdtAmount: cdtTotal.toFixed(2),
        ecsDailyList,
        eipDailyList
      }
    }
  } catch {
    financialBillStatus = "unavailable"
  }
  }

  const color = totalGB >= vpsCutoffReferenceGB
    ? "systemRed"
    : totalGB >= vpsCutoffReferenceGB - 15
      ? "systemOrange"
      : "systemGreen"

  return {
    totalGB,
    thresholdGB,
    vpsCutoffReferenceGB,
    remainingGB,
    percentage,
    daysRemaining,
    dailyBudgetGB,
    monthTimeProgress,
    dailyUsage,
    sevenDayTotalGB,
    todayEstimatedGB,
    updatedAt: now,
    ecsStatus,
    publicIp,
    color,
    financialBalance,
    financialBill,
    financialBillStatus
  }
}

function getTrafficHealthMeta(totalGB: number, cutoffReferenceGB: number, percentage: number, monthTimeProgress: number): {
  label: string
  color: string
  icon: string
} {
  if (totalGB >= cutoffReferenceGB) {
    return { label: `已达到 VPS 熔断参考线 ${cutoffReferenceGB} GB（仅展示）`, color: "systemRed", icon: "exclamationmark.octagon.fill" }
  }
  if (totalGB >= cutoffReferenceGB - 15) {
    return {
      label: `接近 VPS 熔断参考线 ${cutoffReferenceGB} GB，余 ${Math.max(0, cutoffReferenceGB - totalGB).toFixed(1)} GB（仅展示）`,
      color: "systemOrange",
      icon: "exclamationmark.circle.fill"
    }
  }
  if (percentage > monthTimeProgress + 15) {
    return { label: "用量进度快于本月时间进度", color: "systemOrange", icon: "exclamationmark.circle.fill" }
  }
  return { label: "用量进度正常", color: "systemGreen", icon: "checkmark.circle.fill" }
}

function currencySymbol(currency?: string): string {
  if (currency === "USD") return "$"
  if (currency === "CNY" || !currency) return "¥"
  return `${currency} `
}

function humanizeAliyunError(rawMessage: string): string {
  if (!rawMessage) return "未知错误"
  if (rawMessage.includes("InvalidAccessKeyId.NotFound")) {
    return "AccessKey ID 不存在或已失效，请核对凭据。"
  }
  if (rawMessage.includes("SignatureDoesNotMatch")) {
    return "AccessKey Secret 错误导致签名校验失败，请检查 Secret 是否正确。"
  }
  if (rawMessage.includes("InvalidInstanceId.NotFound")) {
    return "找不到指定的 ECS 实例，请核对实例 ID 与所在地域 (Region)。"
  }
  if (rawMessage.includes("Forbidden.RAM") || rawMessage.includes("NoPermission") || rawMessage.includes("Unauthorized")) {
    return "RAM 权限不足：请授予所需只读权限 ecs:DescribeInstances、cdt:ListCdtInternetTraffic；账单功能另需对应 BSS 查询权限。"
  }
  if (rawMessage.includes("IncorrectInstanceStatus")) {
    return "实例当前状态无法执行此操作，请稍候重试。"
  }
  if (rawMessage.includes("OperationDenied.NoStock")) {
    return "当前地域实例资源库存紧张，无法启动。"
  }
  return rawMessage
}

// ==================== 4. 小组件渲染视图 ====================

type ECSStatusMeta = {
  label: string
  shortLabel: string
  color: string
}

function getECSStatusMeta(status: MonitorData["ecsStatus"]): ECSStatusMeta {
  switch (status) {
    case "Running":
      return { label: "运行中", shortLabel: "运行", color: "systemGreen" }
    case "Starting":
      return { label: "启动中", shortLabel: "启动中", color: "systemOrange" }
    case "Stopping":
      return { label: "停止中", shortLabel: "停止中", color: "systemOrange" }
    case "Stopped":
      return { label: "已停止", shortLabel: "停止", color: "secondaryLabel" }
    default:
      return { label: "状态未知", shortLabel: "未知", color: "secondaryLabel" }
  }
}

function TrafficRing({
  data,
  size,
  lineWidth,
  value,
  caption,
  subcaption,
  valueFont,
  captionFont
}: {
  data: MonitorData
  size: number
  lineWidth: number
  value: string
  caption?: string
  subcaption?: string
  valueFont: number
  captionFont?: number
}) {
  const progress = Math.max(0, Math.min(1, data.percentage / 100))

  return (
    <ZStack frame={{ width: size, height: size }} alignment="center">
      <Circle
        stroke={{
          shapeStyle: { light: "rgba(120, 120, 128, 0.20)", dark: "rgba(120, 120, 128, 0.36)" } as any,
          strokeStyle: { lineWidth, lineCap: "round" }
        }}
        frame={{ width: size, height: size }}
      />
      {progress > 0.001 && (
        <Circle
          trim={{ from: 0, to: progress }}
          stroke={{
            shapeStyle: data.color,
            strokeStyle: { lineWidth, lineCap: "round" }
          }}
          rotationEffect={-90}
          widgetAccentable
          frame={{ width: size, height: size }}
        />
      )}
      <VStack spacing={0} alignment="center">
        <Text
          font={valueFont}
          bold
          monospacedDigit
          lineLimit={1}
          minScaleFactor={0.65}
          allowsTightening={true}
          foregroundStyle="label"
        >
          {value}
        </Text>
        {caption && (
          <Text font={Math.max(9, captionFont || 9)} lineLimit={1} foregroundStyle="secondaryLabel">
            {caption}
          </Text>
        )}
        {subcaption && (
          <Text font={Math.max(9, (captionFont || 9) - 1)} lineLimit={1} foregroundStyle="secondaryLabel">
            {subcaption}
          </Text>
        )}
      </VStack>
    </ZStack>
  )
}

function NotConfiguredWidget() {
  return (
    <VStack
      alignment="leading"
      spacing={6}
      padding={14}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <HStack spacing={6} alignment="center">
        <Image systemName="gearshape.fill" font={14} foregroundStyle="systemOrange" />
        <Text font="subheadline" bold foregroundStyle="systemOrange">
          尚未配置
        </Text>
      </HStack>
      <Text font="caption2" foregroundStyle="secondaryLabel">
        请在 Scripting 中打开此脚本完成阿里云凭据配置。
      </Text>
      <Spacer />
      <Text font="caption2" bold foregroundStyle="systemBlue">
        轻点进入配置 &gt;
      </Text>
    </VStack>
  )
}

function SmallWidget({ data }: { data: MonitorData }) {
  return <SmallWidgetView data={data} />
}

// BEGIN SHARED MEDIUM WIDGET: generated from medium_widget.tsx
interface MediumWidgetData {
  totalGB: number
  thresholdGB: number
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  sevenDayTotalGB: number | null
  dailyUsage: Array<{ date: string; label: string; valueGB: number | null; isToday: boolean }>
  updatedAt: Date | string | number
  isCached?: boolean
  ecsStatus: string
  color: string
  accountName?: string
}

// iOS system fill tones: one neutral surface for every panel, colour only for state.
const MEDIUM_COLORS = {
  neutralPanel: { light: "rgba(120, 120, 128, 0.09)", dark: "rgba(120, 120, 128, 0.20)" } as any,
  todayPanel: { light: "rgba(0, 122, 255, 0.10)", dark: "rgba(10, 132, 255, 0.22)" } as any,
  track: { light: "rgba(120, 120, 128, 0.20)", dark: "rgba(120, 120, 128, 0.36)" } as any,
  blue: { light: "#007AFF", dark: "#0A84FF" } as any,
  softBlue: { light: "rgba(0, 122, 255, 0.42)", dark: "rgba(10, 132, 255, 0.52)" } as any,
  green: { light: "#34C759", dark: "#30D158" } as any
}

function planMediumWidgetLayout(
  size?: { width: number; height: number },
  measuredSize?: { width: number; height: number }
) {
  const canvasWidth = Number.isFinite(size?.width) && size!.width > 0 ? size!.width : 329
  const canvasHeight = Number.isFinite(size?.height) && size!.height > 0 ? size!.height : 155
  const availableWidth = Number.isFinite(measuredSize?.width) && measuredSize!.width > 100
    ? measuredSize!.width : canvasWidth - 32
  const availableHeight = Number.isFinite(measuredSize?.height) && measuredSize!.height > 80
    ? measuredSize!.height : canvasHeight - 32
  const small = availableHeight < 123
  const large = availableHeight >= 138
  // Whitespace between the three sections replaces the old per-tile boxes.
  const padding = small ? 3 : large ? 5 : 4
  const gap = small ? 2 : large ? 6 : 5
  const headerHeight = small ? 17 : large ? 20 : 18
  const dailyHeight = small ? 28 : large ? 34 : 32
  const bodyHeight = Math.min(
    small ? 52 : large ? 62 : 56,
    availableHeight - padding * 2 - headerHeight - dailyHeight - gap * 2
  )
  // A measured container already accounts for the host's system margins.
  const contentWidth = Math.floor(availableWidth - padding * 2)
  const usageWidth = Math.floor(contentWidth * 0.42)
  const metricsWidth = contentWidth - usageWidth - gap
  const tileWidth = (metricsWidth - gap) / 2
  const tileHeight = (bodyHeight - gap) / 2
  const dailyColumnWidth = (contentWidth - 34 - 6) / 7
  const contentHeight = padding * 2 + headerHeight + bodyHeight + dailyHeight + gap * 2

  return {
    canvasWidth, canvasHeight, availableWidth, availableHeight, contentWidth, padding, gap, headerHeight,
    bodyHeight, dailyHeight, usageWidth, metricsWidth, tileWidth, tileHeight,
    dailyColumnWidth, contentHeight
  }
}

function formatDailyUsage(value: number | null): string {
  if (value === null || !Number.isFinite(value) || value < 0) return "--"
  if (value > 0 && value < 0.01) return "<0.01"
  return String(Number(value.toFixed(2)))
}

function mediumStatus(status: string): { label: string; color: any } {
  switch (status) {
    case "Running":
      return { label: "运行", color: MEDIUM_COLORS.green }
    case "Starting":
      return { label: "启动中", color: "systemOrange" }
    case "Stopping":
      return { label: "停止中", color: "systemOrange" }
    case "Stopped":
      return { label: "停止", color: "secondaryLabel" }
    default:
      return { label: "未知", color: "secondaryLabel" }
  }
}

function mediumUpdateTime(value: MediumWidgetData["updatedAt"]): string {
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) return "--:--"
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`
}

function MediumMetric({
  label, value, unit, width, height, color = "label"
}: { label: string; value: string; unit: string; width: number; height: number; color?: any }) {
  return (
    <VStack alignment="leading" spacing={0} frame={{ width, height, alignment: "topLeading" }}>
      <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={13} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.75} foregroundStyle={color}>
          {value}
        </Text>
        <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>{unit}</Text>
      </HStack>
    </VStack>
  )
}

function DailyUsageStrip({
  data, layout
}: { data: MediumWidgetData; layout: ReturnType<typeof planMediumWidgetLayout> }) {
  return (
    <ZStack frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
      <RoundedRectangle
        cornerRadius={8}
        style="continuous"
        fill={MEDIUM_COLORS.neutralPanel}
        frame={{ width: layout.contentWidth, height: layout.dailyHeight }}
      />
      <HStack spacing={0} alignment="center" frame={{ width: layout.contentWidth, height: layout.dailyHeight }}>
        <VStack spacing={0} alignment="center" frame={{ width: 34, height: layout.dailyHeight }}>
          <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>每日</Text>
          <Text font={8} foregroundStyle="tertiaryLabel" lineLimit={1}>GB</Text>
        </VStack>
        {data.dailyUsage.slice(-7).map(point => (
          <HStack key={point.date} spacing={0} alignment="center">
            <ZStack frame={{ width: layout.dailyColumnWidth, height: layout.dailyHeight }}>
              {point.isToday && (
                <RoundedRectangle
                  cornerRadius={7}
                  style="continuous"
                  fill={MEDIUM_COLORS.todayPanel}
                  frame={{ width: layout.dailyColumnWidth - 2, height: layout.dailyHeight - 4 }}
                />
              )}
              <VStack spacing={1} alignment="center" padding={{ horizontal: 2 }}>
                <Text
                  font={11}
                  fontWeight="semibold"
                  monospacedDigit
                  lineLimit={1}
                  minScaleFactor={0.75}
                  widgetAccentable={point.isToday}
                  foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : point.valueGB === null ? "tertiaryLabel" : "label"}
                >
                  {formatDailyUsage(point.valueGB)}
                </Text>
                <Text font={9} lineLimit={1} widgetAccentable={point.isToday} foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : "secondaryLabel"}>
                  {point.isToday ? "今天" : point.label}
                </Text>
              </VStack>
            </ZStack>
          </HStack>
        ))}
      </HStack>
    </ZStack>
  )
}

function MediumWidgetContent({
  data, layout
}: { data: MediumWidgetData; layout: ReturnType<typeof planMediumWidgetLayout> }) {
  const status = mediumStatus(data.ecsStatus)
  const usageColor = data.color === "systemGreen" ? MEDIUM_COLORS.blue : data.color
  const trackWidth = layout.usageWidth - 12
  const progress = Math.max(0, Math.min(1, data.percentage / 100))

  return (
    <VStack
      alignment="center"
      spacing={layout.gap}
      padding={layout.padding}
      widgetBackground="systemBackground"
    >
      <HStack spacing={5} alignment="center" frame={{ width: layout.contentWidth, height: layout.headerHeight }}>
        <Image systemName="cloud.fill" font={12} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
        <Text font={12} fontWeight="semibold" lineLimit={1} foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          {data.accountName ? `阿里云 CDT · ${data.accountName}` : "阿里云 CDT"}
        </Text>
        <HStack spacing={4} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
          <Text font={10} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
            {status.label} · {data.isCached ? "缓存 " : ""}{mediumUpdateTime(data.updatedAt)}
          </Text>
        </HStack>
      </HStack>

      <HStack spacing={layout.gap} alignment="top" frame={{ width: layout.contentWidth, height: layout.bodyHeight }}>
        {/* 主信息：本月用量，不加底色，靠字号建立层级 */}
        <VStack alignment="leading" spacing={3} padding={{ leading: 4 }} frame={{ width: layout.usageWidth, height: layout.bodyHeight, alignment: "topLeading" }}>
          <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
          <HStack alignment="lastTextBaseline" spacing={2}>
            <Text font={24} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
              {data.totalGB.toFixed(2)}
            </Text>
            <Text font={11} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
          </HStack>
          <ZStack alignment="leading" frame={{ width: trackWidth, height: 5 }}>
            <RoundedRectangle cornerRadius={2.5} fill={MEDIUM_COLORS.track} frame={{ width: trackWidth, height: 5 }} />
            {progress > 0 && (
              <RoundedRectangle widgetAccentable cornerRadius={2.5} fill={usageColor} frame={{ width: Math.max(5, trackWidth * progress), height: 5 }} />
            )}
          </ZStack>
          <HStack spacing={2} alignment="center" frame={{ width: trackWidth }}>
            <Text font={9} monospacedDigit lineLimit={1} minScaleFactor={0.9} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
              共 {data.thresholdGB} GB
            </Text>
            <Text font={9} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
              {data.percentage.toFixed(1)}%
            </Text>
          </HStack>
        </VStack>

        {/* 次要指标：无底色 2×2 网格，与左侧标签顶部对齐 */}
        <VStack spacing={layout.gap} frame={{ width: layout.metricsWidth, height: layout.bodyHeight, alignment: "topLeading" }}>
          <HStack spacing={layout.gap} alignment="top">
            <MediumMetric label="参考余量" value={data.remainingGB.toFixed(1)} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetric label="日均可用" value={data.dailyBudgetGB} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
          </HStack>
          <HStack spacing={layout.gap} alignment="top">
            <MediumMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={layout.tileWidth} height={layout.tileHeight} />
            <MediumMetric label="近 7 日" value={formatDailyUsage(data.sevenDayTotalGB)} unit="GB" width={layout.tileWidth} height={layout.tileHeight} />
          </HStack>
        </VStack>
      </HStack>

      <DailyUsageStrip data={data} layout={layout} />
    </VStack>
  )
}

function MediumWidgetView({ data }: { data: MediumWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const layout = planMediumWidgetLayout(Widget.displaySize, proxy.size)
        return (
          <ZStack alignment="center" frame={{ width: layout.availableWidth, height: layout.availableHeight }}>
            <MediumWidgetContent data={data} layout={layout} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}

// ==================== Small / Large share the medium widget's visual language ====================

interface SystemWidgetData extends MediumWidgetData {
  todayEstimatedGB?: number | null
}

function widgetUsageColor(data: MediumWidgetData): any {
  return data.color === "systemGreen" ? MEDIUM_COLORS.blue : data.color
}

function WidgetTitleRow({ data, compact = false }: { data: MediumWidgetData; compact?: boolean }) {
  const status = mediumStatus(data.ecsStatus)
  return (
    <HStack spacing={5} alignment="center" frame={{ maxWidth: Infinity }}>
      <Image systemName="cloud.fill" font={compact ? 11 : 13} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
      <Text font={compact ? 11 : 13} fontWeight="semibold" lineLimit={1} foregroundStyle="label">
        {compact ? (data.accountName || "CDT") : (data.accountName ? `阿里云 CDT · ${data.accountName}` : "阿里云 CDT")}
      </Text>
      <Spacer />
      <HStack spacing={4} alignment="center">
        <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
        <Text font={compact ? 9 : 11} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {`${status.label} · ${data.isCached ? "缓存 " : ""}${mediumUpdateTime(data.updatedAt)}`}
        </Text>
      </HStack>
    </HStack>
  )
}

function UsageBar({ data, width, height = 5 }: { data: MediumWidgetData; width: number; height?: number }) {
  const progress = Math.max(0, Math.min(1, data.percentage / 100))
  const radius = height / 2
  return (
    <ZStack alignment="leading" frame={{ width, height }}>
      <RoundedRectangle cornerRadius={radius} fill={MEDIUM_COLORS.track} frame={{ width, height }} />
      {progress > 0 && (
        <RoundedRectangle widgetAccentable cornerRadius={radius} fill={widgetUsageColor(data)} frame={{ width: Math.max(height, width * progress), height }} />
      )}
    </ZStack>
  )
}

function SmallWidgetContent({ data, width, height }: { data: SystemWidgetData; width: number; height: number }) {
  return (
    <VStack alignment="leading" spacing={0} frame={{ width, height, alignment: "topLeading" }}>
      <WidgetTitleRow data={data} compact />
      <Spacer />
      <Text font={9} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={26} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
          {data.totalGB.toFixed(2)}
        </Text>
        <Text font={11} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
      </HStack>
      <Spacer />
      <UsageBar data={data} width={width} />
      <HStack spacing={2} alignment="center" frame={{ width }} padding={{ top: 3 }}>
        <Text font={9} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          共 {data.thresholdGB} GB
        </Text>
        <Text font={9} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {data.percentage.toFixed(1)}%
        </Text>
      </HStack>
      <Spacer />
      <HStack spacing={6} alignment="top" frame={{ width }}>
        <MediumMetric label="参考余量" value={data.remainingGB.toFixed(1)} unit="GB" width={(width - 6) / 2} height={28} />
        <MediumMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={(width - 6) / 2} height={28} />
      </HStack>
    </VStack>
  )
}

function SmallWidgetView({ data }: { data: SystemWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const fallback = Widget.displaySize?.width > 0 ? Widget.displaySize.width - 28 : 130
        const width = Number.isFinite(proxy?.size?.width) && proxy.size.width > 80 ? Math.floor(proxy.size.width) : fallback
        const height = Number.isFinite(proxy?.size?.height) && proxy.size.height > 80 ? Math.floor(proxy.size.height) : width
        return (
          <ZStack alignment="topLeading" frame={{ width, height }}>
            <SmallWidgetContent data={data} width={width} height={height} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}

function DailyUsageBars({ data, width, chartHeight }: { data: SystemWidgetData; width: number; chartHeight: number }) {
  const points = data.dailyUsage.slice(-7)
  const known = points.map(point => point.valueGB).filter((value): value is number => value !== null && Number.isFinite(value))
  const maximum = Math.max(0.01, ...known)
  const columnWidth = width / 7
  const barWidth = Math.min(22, Math.max(10, columnWidth - 14))
  return (
    <ZStack frame={{ width, height: chartHeight + 44 }}>
      <RoundedRectangle cornerRadius={8} style="continuous" fill={MEDIUM_COLORS.neutralPanel} frame={{ width, height: chartHeight + 44 }} />
      <HStack spacing={0} alignment="bottom" frame={{ width, height: chartHeight + 44 }}>
        {points.map(point => {
          const value = point.valueGB
          const fillHeight = value === null || value <= 0 ? 0 : Math.max(4, Math.round((value / maximum) * chartHeight))
          const tint = point.isToday ? MEDIUM_COLORS.blue : MEDIUM_COLORS.softBlue
          return (
            <VStack key={point.date} spacing={3} alignment="center" frame={{ width: columnWidth }} padding={{ vertical: 5 }}>
              <Text
                font={10}
                fontWeight={point.isToday ? "semibold" : "regular"}
                monospacedDigit
                lineLimit={1}
                minScaleFactor={0.8}
                foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : value === null ? "tertiaryLabel" : "secondaryLabel"}
              >
                {formatDailyUsage(value)}
              </Text>
              <ZStack alignment="bottom" frame={{ width: barWidth, height: chartHeight }}>
                <RoundedRectangle cornerRadius={4} style="continuous" fill={MEDIUM_COLORS.track} frame={{ width: barWidth, height: chartHeight }} />
                {fillHeight > 0 && (
                  <RoundedRectangle widgetAccentable={point.isToday} cornerRadius={4} style="continuous" fill={tint} frame={{ width: barWidth, height: fillHeight }} />
                )}
              </ZStack>
              <Text font={10} lineLimit={1} foregroundStyle={point.isToday ? MEDIUM_COLORS.blue : "secondaryLabel"}>
                {point.isToday ? "今天" : point.label}
              </Text>
            </VStack>
          )
        })}
      </HStack>
    </ZStack>
  )
}

function LargeWidgetContent({ data, width, height }: { data: SystemWidgetData; width: number; height: number }) {
  const gap = 10
  const tileWidth = (width - gap) / 2
  // 每个区块都用固定高度，图表高度吃掉剩余空间，区块间距按余量自适应，
  // 这样无论机型的大号组件有多高，内容总高度都不会超出可用高度。
  const fixedHeight = 216
  const free = height - 4 - fixedHeight
  const chartHeight = Math.max(28, Math.min(96, Math.floor(free - 40)))
  const sectionGap = Math.max(4, Math.min(14, Math.floor((free - chartHeight) / 5)))
  return (
    <VStack alignment="leading" spacing={sectionGap} frame={{ width, height, alignment: "topLeading" }}>
      <VStack alignment="leading" spacing={0} frame={{ width, height: 16, alignment: "leading" }}>
        <WidgetTitleRow data={data} />
      </VStack>
      <VStack alignment="leading" spacing={0} frame={{ width, height: 56, alignment: "topLeading" }}>
        <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>本月出网</Text>
        <HStack alignment="lastTextBaseline" spacing={3} frame={{ width }}>
          <Text font={34} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
            {data.totalGB.toFixed(2)}
          </Text>
          <Text font={14} fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
          <Spacer />
          <Text font={12} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
            {data.percentage.toFixed(1)}% · 共 {data.thresholdGB} GB
          </Text>
        </HStack>
      </VStack>
      <UsageBar data={data} width={width} height={6} />
      <VStack spacing={8} alignment="leading" frame={{ width, height: 80, alignment: "topLeading" }}>
        <HStack spacing={gap} alignment="top">
          <LargeMetric label="参考余量" value={data.remainingGB.toFixed(2)} unit="GB" width={tileWidth} />
          <LargeMetric label="日均可用" value={data.dailyBudgetGB} unit="GB" width={tileWidth} />
        </HStack>
        <HStack spacing={gap} alignment="top">
          <LargeMetric label="距结算" value={String(data.daysRemaining)} unit="天" width={tileWidth} />
          <LargeMetric label="近 7 日" value={formatDailyUsage(data.sevenDayTotalGB)} unit="GB" width={tileWidth} />
        </HStack>
      </VStack>
      <HStack alignment="center" frame={{ width, height: 14 }}>
        <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>每日用量</Text>
        <Spacer />
        <Text font={10} foregroundStyle="tertiaryLabel" lineLimit={1}>本机采样估算 · GB</Text>
      </HStack>
      <DailyUsageBars data={data} width={width} chartHeight={chartHeight} />
    </VStack>
  )
}

function LargeMetric({ label, value, unit, width }: { label: string; value: string; unit: string; width: number }) {
  return (
    <VStack alignment="leading" spacing={1} frame={{ width, height: 36, alignment: "topLeading" }}>
      <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={17} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.75} foregroundStyle="label">
          {value}
        </Text>
        <Text font={11} foregroundStyle="secondaryLabel" lineLimit={1}>{unit}</Text>
      </HStack>
    </VStack>
  )
}

function LargeWidgetView({ data }: { data: SystemWidgetData }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const fallbackWidth = Widget.displaySize?.width > 0 ? Widget.displaySize.width - 32 : 297
        const fallbackHeight = Widget.displaySize?.height > 0 ? Widget.displaySize.height - 32 : 313
        const width = Number.isFinite(proxy?.size?.width) && proxy.size.width > 150 ? Math.floor(proxy.size.width) : fallbackWidth
        const height = Number.isFinite(proxy?.size?.height) && proxy.size.height > 200 ? Math.floor(proxy.size.height) : fallbackHeight
        return (
          <ZStack alignment="topLeading" frame={{ width, height }}>
            <LargeWidgetContent data={data} width={width} height={height} />
          </ZStack>
        )
      }}
    </GeometryReader>
  )
}

// ==================== Multi-account summary: one panel per account ====================

export interface AccountWidgetItem {
  name: string
  site?: string
  data: MediumWidgetData | null
  error?: string
}

function accountSiteTag(site?: string): string {
  return site === "intl" ? "国际站" : "中国站"
}

function latestUpdateLabel(items: AccountWidgetItem[]): string {
  let latest = 0
  let cached = false
  for (const item of items) {
    if (!item.data) continue
    const date = item.data.updatedAt instanceof Date ? item.data.updatedAt : new Date(item.data.updatedAt)
    if (Number.isFinite(date.getTime()) && date.getTime() > latest) latest = date.getTime()
    if (item.data.isCached) cached = true
  }
  return latest > 0 ? `${cached ? "含缓存 · " : ""}${mediumUpdateTime(new Date(latest))}` : "--:--"
}

function AccountPanel({
  item, width, height, compact
}: { item: AccountWidgetItem; width: number; height: number; compact: boolean }) {
  const inset = compact ? 6 : 10
  const roomy = !compact && height >= 110
  const innerWidth = Math.max(40, width - inset * 2)
  const innerHeight = Math.max(24, height - inset * 2)
  const data = item.data
  const status = mediumStatus(data?.ecsStatus ?? "Unknown")
  return (
    <ZStack alignment="center" frame={{ width, height }}>
      <RoundedRectangle cornerRadius={compact ? 10 : 12} style="continuous" fill={MEDIUM_COLORS.neutralPanel} frame={{ width, height }} />
      <VStack alignment="leading" spacing={0} frame={{ width: innerWidth, height: innerHeight, alignment: "topLeading" }}>
        <HStack spacing={4} alignment="center" frame={{ width: innerWidth }}>
          <Circle widgetAccentable fill={data ? status.color : "systemRed"} frame={{ width: 6, height: 6 }} />
          <Text font={compact ? 11 : 12} fontWeight="semibold" lineLimit={1} minScaleFactor={0.8} foregroundStyle="label">
            {item.name}
          </Text>
          <Spacer />
          <Text font={9} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
            {!data ? accountSiteTag(item.site) : compact ? `${data.percentage.toFixed(0)}%` : `${status.label}${data.isCached ? " · 缓存" : ""}`}
          </Text>
        </HStack>
        <Spacer />
        {data ? (
          <VStack alignment="leading" spacing={compact ? 3 : 4}>
            <HStack alignment="lastTextBaseline" spacing={2}>
              <Text font={compact ? 17 : 20} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.6} foregroundStyle="label">
                {data.totalGB.toFixed(2)}
              </Text>
              <Text font={compact ? 9 : 10} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                / {data.thresholdGB} GB
              </Text>
            </HStack>
            <UsageBar data={data} width={innerWidth} height={compact ? 4 : 5} />
            {!compact && <HStack spacing={2} alignment="center" frame={{ width: innerWidth }}>
              <Text font={9} monospacedDigit lineLimit={1} minScaleFactor={0.8} foregroundStyle="secondaryLabel" frame={{ maxWidth: Infinity, alignment: "leading" }}>
                余 {data.remainingGB.toFixed(1)} GB
              </Text>
              <Text font={9} fontWeight="semibold" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                {data.percentage.toFixed(1)}%
              </Text>
            </HStack>}
            {roomy && (
              <Text font={9} monospacedDigit lineLimit={1} minScaleFactor={0.8} foregroundStyle="tertiaryLabel">
                日均可用 {data.dailyBudgetGB} GB · 近 7 日 {formatDailyUsage(data.sevenDayTotalGB)} GB
              </Text>
            )}
          </VStack>
        ) : (
          <VStack alignment="leading" spacing={2}>
            <Text font={compact ? 12 : 13} fontWeight="semibold" foregroundStyle="systemRed" lineLimit={1}>获取失败</Text>
            <Text font={9} foregroundStyle="secondaryLabel" lineLimit={2} minScaleFactor={0.8}>
              {item.error || "请在 App 内检查该账号配置"}
            </Text>
          </VStack>
        )}
      </VStack>
    </ZStack>
  )
}

function MultiAccountHeader({ items, width, compact }: { items: AccountWidgetItem[]; width: number; compact: boolean }) {
  const days = items.find(item => item.data)?.data?.daysRemaining
  return (
    <HStack spacing={5} alignment="center" frame={{ width }}>
      <Image systemName="cloud.fill" font={compact ? 11 : 12} widgetAccentable foregroundStyle={MEDIUM_COLORS.blue} />
      <Text font={compact ? 11 : 12} fontWeight="semibold" lineLimit={1} foregroundStyle="label">
        {compact ? "CDT" : "阿里云 CDT"}
      </Text>
      <Spacer />
      <Text font={compact ? 9 : 10} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
        {compact || days === undefined ? latestUpdateLabel(items) : `距结算 ${days} 天 · ${latestUpdateLabel(items)}`}
      </Text>
    </HStack>
  )
}

function MultiAccountWidgetView({ items, family }: { items: AccountWidgetItem[]; family?: string }) {
  return (
    <GeometryReader widgetBackground="systemBackground">
      {proxy => {
        const display = Widget.displaySize
        const fallbackWidth = display?.width > 0 ? display.width - 32 : 297
        const fallbackHeight = display?.height > 0 ? display.height - 32 : 123
        const width = Number.isFinite(proxy?.size?.width) && proxy.size.width > 80 ? Math.floor(proxy.size.width) : fallbackWidth
        const height = Number.isFinite(proxy?.size?.height) && proxy.size.height > 60 ? Math.floor(proxy.size.height) : fallbackHeight
        const compact = family === "systemSmall" || width < 200
        const gap = compact ? 6 : 8
        const headerHeight = compact ? 16 : 18
        const visible = items.slice(0, compact ? 2 : family === "systemLarge" ? 4 : 2)
        const count = Math.max(1, visible.length)
        // 中号两账号左右并排；小号和大号上下排列。
        const sideBySide = !compact && family !== "systemLarge" && count <= 2
        const bodyHeight = height - headerHeight - gap
        const panelWidth = sideBySide ? (width - gap * (count - 1)) / count : width
        const panelHeight = sideBySide ? bodyHeight : (bodyHeight - gap * (count - 1)) / count
        const panels = visible.map((item, index) => (
          <AccountPanel key={`${index}-${item.name}`} item={item} width={panelWidth} height={panelHeight} compact={compact} />
        ))
        return (
          <VStack alignment="leading" spacing={gap} frame={{ width, height, alignment: "topLeading" }}>
            <MultiAccountHeader items={items} width={width} compact={compact} />
            {sideBySide
              ? <HStack spacing={gap} alignment="top">{panels}</HStack>
              : <VStack spacing={gap} alignment="leading">{panels}</VStack>}
          </VStack>
        )
      }}
    </GeometryReader>
  )
}

function MediumWidget({ data }: { data: MonitorData }) {
  return <MediumWidgetView data={data} />
}
// END SHARED MEDIUM WIDGET

function LargeWidget({ data }: { data: MonitorData }) {
  return <LargeWidgetView data={data} />
}

function AccessoryRectangularWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <HStack
      alignment="center"
      spacing={9}
      widgetBackground="clear"
      frame={{ maxWidth: Infinity, maxHeight: Infinity, alignment: "leading" }}
    >
      <TrafficRing
        data={data}
        size={46}
        lineWidth={5}
        value={`${data.percentage.toFixed(1)}%`}
        valueFont={10}
      />
      <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
        <HStack alignment="center">
          <Text font={14} bold monospacedDigit lineLimit={1}>
            {data.totalGB.toFixed(2)} GB
          </Text>
          <Spacer />
          <HStack spacing={4} alignment="center">
            <Circle widgetAccentable fill={status.color} frame={{ width: 5, height: 5 }} />
            <Text font={9} lineLimit={1} foregroundStyle="secondaryLabel">
              {data.isCached ? "缓存 · " : ""}{status.shortLabel}
            </Text>
          </HStack>
        </HStack>
        <Text font={9} lineLimit={1} foregroundStyle="secondaryLabel">
          {data.accountName ? `${data.accountName} · ` : ""}参考余量 {data.remainingGB.toFixed(1)} GB · 距结算 {data.daysRemaining} 天
        </Text>
      </VStack>
    </HStack>
  )
}

function AccessoryInlineWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <Text lineLimit={1} monospacedDigit>
      {data.accountName ? `${data.accountName} · ` : ""}CDT {data.totalGB.toFixed(2)}/{data.thresholdGB}G · {data.isCached ? "缓存" : status.shortLabel}
    </Text>
  )
}

function AccessoryCircularWidget({ data }: { data: MonitorData }) {
  return (
    <ZStack
      widgetBackground="clear"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
      alignment="center"
    >
      <TrafficRing
        data={data}
        size={50}
        lineWidth={5}
        value={`${Math.round(data.percentage)}%`}
        caption={data.isCached ? "缓存" : "CDT"}
        valueFont={11}
        captionFont={9}
      />
    </ZStack>
  )
}

const WIDGET_RELOAD_INTERVAL_MS = 15 * 60 * 1000

function presentWidget(element: any): void {
  Widget.present(element, {
    policy: "after",
    date: new Date(Date.now() + WIDGET_RELOAD_INTERVAL_MS)
  })
}

function presentMonitorWidget(data: MonitorData): void {
  if (Widget.family === "accessoryInline") {
    presentWidget(<AccessoryInlineWidget data={data} />)
  } else if (Widget.family === "accessoryCircular") {
    presentWidget(<AccessoryCircularWidget data={data} />)
  } else if (Widget.family === "accessoryRectangular") {
    presentWidget(<AccessoryRectangularWidget data={data} />)
  } else if (Widget.family === "systemLarge") {
    presentWidget(<LargeWidget data={data} />)
  } else if (Widget.family === "systemMedium") {
    presentWidget(<MediumWidget data={data} />)
  } else {
    presentWidget(<SmallWidget data={data} />)
  }
}

// ==================== 5. 设置配置面板视图 ====================

function maskAccessKeyId(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) return ""

  const suffixLength = Math.min(4, Math.max(0, trimmed.length - 1))
  const suffix = suffixLength > 0 ? trimmed.slice(-suffixLength) : ""
  return `••••${suffix}`
}

const CARD_FILL = { light: "#FFFFFF", dark: "#1C1C1E" } as any

function dashboardSurface(cornerRadius: number = 18) {
  return {
    background: CARD_FILL,
    clipShape: { type: "rect" as const, cornerRadius, style: "continuous" as const }
  }
}

/** Settings-style rounded icon tile: solid system colour with a white glyph. */
function IconTile({ systemName, color, size = 30 }: { systemName: string; color: string; size?: number }) {
  return (
    <ZStack
      frame={{ width: size, height: size }}
      background={color}
      clipShape={{ type: "rect", cornerRadius: size * 0.26, style: "continuous" }}
    >
      <Image systemName={systemName} font={size * 0.5} fontWeight="semibold" foregroundStyle="#FFFFFF" />
    </ZStack>
  )
}

function SectionFootnote({ children }: { children: any }) {
  return (
    <Text font="footnote" foregroundStyle="secondaryLabel" padding={{ horizontal: 16 }} frame={{ maxWidth: Infinity, alignment: "leading" }}>
      {children}
    </Text>
  )
}

function DashboardSectionHeader({
  title,
  detail,
  trailing
}: {
  title: string
  detail?: string
  trailing?: any
}) {
  return (
    <HStack padding={{ horizontal: 16, top: 14 }} alignment="center">
      <Text font="footnote" foregroundStyle="secondaryLabel">
        {title}
      </Text>
      <Spacer />
      {trailing ?? (detail ? (
        <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>
          {detail}
        </Text>
      ) : null)}
    </HStack>
  )
}

function UsageMetric({ label, value, unit, color = "label" }: { label: string; value: string; unit: string; color?: string }) {
  return (
    <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
      <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>{label}</Text>
      <HStack alignment="lastTextBaseline" spacing={2}>
        <Text font={22} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.7} foregroundStyle={color}>{value}</Text>
        <Text font="caption1" foregroundStyle="secondaryLabel">{unit}</Text>
      </HStack>
    </VStack>
  )
}

/** Native Settings-style row: the whole row is tappable, value sits on the trailing edge. */
function SettingsRow({
  icon,
  iconColor,
  title,
  detail,
  detailColor = "secondaryLabel",
  action,
  accessibilityLabel
}: {
  icon: string
  iconColor: string
  title: string
  detail: string
  detailColor?: string
  action: () => void
  accessibilityLabel: string
}) {
  return (
    <Button action={action} buttonStyle="plain" accessibilityLabel={accessibilityLabel} frame={{ maxWidth: Infinity }}>
      <HStack alignment="center" spacing={12} padding={{ vertical: 2 }} frame={{ maxWidth: Infinity }}>
        <IconTile systemName={icon} color={iconColor} size={29} />
        <Text font="body" foregroundStyle="label" lineLimit={1}>{title}</Text>
        <Spacer />
        <Text font="body" foregroundStyle={detailColor} lineLimit={1} minScaleFactor={0.75}>{detail}</Text>
        <Image systemName="chevron.right" font={13} fontWeight="semibold" foregroundStyle="tertiaryLabel" />
      </HStack>
    </Button>
  )
}

/** Fallback grouped card for Scripting builds without List. */
function SettingsCard({ children }: { children: any }) {
  return (
    <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface(12)}>
      {children}
    </VStack>
  )
}

function SettingsCardRow({ children }: { children: any }) {
  return <VStack padding={{ horizontal: 16, vertical: 9 }}>{children}</VStack>
}

function SettingsNotice({ kind, text }: { kind: "error" | "success"; text: string }) {
  const color = kind === "error" ? "systemRed" : "systemGreen"
  return (
    <HStack alignment="top" spacing={8} padding={{ vertical: 2 }}>
      <Image
        systemName={kind === "error" ? "exclamationmark.triangle.fill" : "checkmark.circle.fill"}
        font="subheadline"
        foregroundStyle={color}
      />
      <Text font="subheadline" foregroundStyle="label" lineLimit={4} frame={{ maxWidth: Infinity, alignment: "leading" }}>
        {text}
      </Text>
    </HStack>
  )
}

function SettingsComponent({
  currentConfig,
  onSave,
  onCancel,
  onDelete,
  cancelable
}: {
  currentConfig: AppConfig
  onSave: (newConfig: AppConfig) => void
  onCancel: () => void
  onDelete?: (id: string) => void
  cancelable?: boolean
}) {
  const [ak, setAk] = useState(currentConfig.accessKeyId || "")
  const [sk, setSk] = useState(currentConfig.accessKeySecret || "")
  const [region, setRegion] = useState(currentConfig.regionId || "cn-hongkong")
  const [ecsId, setEcsId] = useState(currentConfig.ecsInstanceId || "")
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || DEFAULT_CONFIG.trafficThresholdGB))
  const [cutoffReference, setCutoffReference] = useState(String(currentConfig.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB))
  const [errorNotice, setErrorNotice] = useState<string | null>(null)
  const [successNotice, setSuccessNotice] = useState<string | null>(null)
  const [accountName, setAccountName] = useState(currentConfig.name || "")
  const [site, setSite] = useState(currentConfig.site === "intl" ? "intl" : "cn")
  const [accountId, setAccountId] = useState(currentConfig.id || "")
  const [siteDrafts, setSiteDrafts] = useState<Record<string, any>>({})

  // 智能剪贴板识别与导入
  const handleSmartPaste = async () => {
    try {
      let text = ""
      if (typeof Pasteboard !== "undefined" && (Pasteboard as any)?.getString) {
        text = ((await Pasteboard.getString()) as string) || ""
      }
      if (!text.trim()) {
        if (typeof Dialog !== "undefined" && Dialog.alert) {
          await Dialog.alert({
            title: "剪贴板为空",
            message: "请先在微信或备忘录中复制包含阿里云 AccessKey 或实例 ID 的文本，再点击智能识别。"
          })
        } else {
          setErrorNotice("剪贴板为空，请先复制凭据信息。")
        }
        return
      }

      let count = 0
      const akMatch = text.match(/LTAI[A-Za-z0-9]{16,24}/i)
      if (akMatch) {
        setAk(akMatch[0].trim())
        count++
      }

      const ecsMatch = text.match(/i-[a-z0-9]{16,24}/i)
      if (ecsMatch) {
        setEcsId(ecsMatch[0].trim())
        count++
      }

      const regMatch = text.match(/(cn-[a-z0-9-]+|ap-[a-z0-9-]+|us-[a-z0-9-]+)/i)
      if (regMatch) {
        setRegion(regMatch[0].trim())
      }

      const secretLabelMatch = text.match(/(?:Secret|SecretKey|KeySecret)[\s:=]*([A-Za-z0-9]{28,34})/i)
      if (secretLabelMatch) {
        setSk(secretLabelMatch[1].trim())
        count++
      } else {
        const tokens = text.match(/[A-Za-z0-9]{28,34}/g)
        if (tokens) {
          for (const t of tokens) {
            if (!t.startsWith("LTAI") && !t.startsWith("i-")) {
              setSk(t.trim())
              count++
              break
            }
          }
        }
      }

      if (count > 0) {
        setErrorNotice(null)
        setSuccessNotice(`已从剪贴板识别并填入 ${count} 项配置`)
        // 凭据已读入，立即清空剪贴板，避免 Secret 留在系统剪贴板被其他 App 读取。
        try {
          if (typeof Pasteboard !== "undefined" && (Pasteboard as any)?.setString) {
            await (Pasteboard as any).setString("")
          }
        } catch {}
        if (typeof Dialog !== "undefined" && Dialog.alert) {
          await Dialog.alert({
            title: "识别成功",
            message: `已填入 ${count} 项阿里云信息，剪贴板已清空。确认无误后点击保存。`
          })
        }
      } else {
        setErrorNotice("未能从剪贴板识别出阿里云凭据格式，请逐项点击下方条目手动填写。")
      }
    } catch (err: any) {
      setErrorNotice("读取剪贴板失败: " + (err?.message || String(err)))
    }
  }

  // 弹窗输入辅助函数
  const promptField = async (
    title: string,
    message: string,
    currentVal: string,
    placeholder: string,
    onConfirm: (val: string) => void,
    secret = false
  ) => {
    if (typeof Dialog !== "undefined" && Dialog.prompt) {
      // Secrets are never echoed back; leaving the masked field empty keeps the saved value.
      const res = await Dialog.prompt({
        title,
        message,
        defaultValue: secret ? "" : currentVal,
        placeholder,
        obscureText: secret,
        confirmLabel: "确定",
        cancelLabel: "取消"
      } as any)
      if (res !== null && res !== undefined) {
        const value = res.trim()
        if (secret && !value) return
        onConfirm(value)
      }
    }
  }

  const REGION_PRESETS = [
    { id: "cn-hongkong", label: "中国香港 (cn-hongkong)" },
    { id: "cn-hangzhou", label: "华东1 杭州 (cn-hangzhou)" },
    { id: "cn-shanghai", label: "华东2 上海 (cn-shanghai)" },
    { id: "cn-beijing", label: "华北2 北京 (cn-beijing)" },
    { id: "cn-shenzhen", label: "华南1 深圳 (cn-shenzhen)" },
    { id: "ap-southeast-1", label: "新加坡 (ap-southeast-1)" },
    { id: "ap-northeast-1", label: "日本东京 (ap-northeast-1)" },
    { id: "us-west-1", label: "美国硅谷 (us-west-1)" }
  ]

  const handleSelectRegion = async () => {
    if (typeof Dialog !== "undefined" && Dialog.actionSheet) {
      const actions = REGION_PRESETS.map(item => ({
        label: `${item.label}${region === item.id ? " ✓" : ""}`
      }))
      actions.push({ label: "其他地域…" })

      const idx = await Dialog.actionSheet({
        title: "选择 ECS 所在地域",
        message: "请选择实例部署的物理 Region ID",
        cancelButton: true,
        actions
      })

      if (idx !== null && idx >= 0) {
        if (idx < REGION_PRESETS.length) {
          setRegion(REGION_PRESETS[idx].id)
        } else if (idx === REGION_PRESETS.length) {
          promptField("设置 ECS 地域", "请输入阿里云 Region ID (如 cn-guangzhou)", region, "cn-hongkong", setRegion)
        }
      }
    } else {
      promptField("设置 ECS 地域", "请输入阿里云 Region ID", region, "cn-hongkong", setRegion)
    }
  }

  // 切换站点 = 切换到另一个账号：当前表单存为草稿，载入目标站点已保存（或之前输入）的内容，
  // 目标站点还没有账号时清空，让用户重新输入；切回来时原内容原样还原。
  const applySite = (next: string) => {
    if (next === site) return
    const drafts = {
      ...siteDrafts,
      [site]: { ak, sk, region, ecsId, threshold, cutoffReference, accountName, accountId }
    }
    setSiteDrafts(drafts)
    let target = drafts[next]
    if (!target) {
      const saved = loadAccountProfiles<AppConfig>(DEFAULT_CONFIG).find(item => (item.site === "intl" ? "intl" : "cn") === next)
      target = saved
        ? {
            ak: saved.accessKeyId || "",
            sk: saved.accessKeySecret || "",
            region: saved.regionId || "cn-hongkong",
            ecsId: saved.ecsInstanceId || "",
            threshold: String(saved.trafficThresholdGB || DEFAULT_CONFIG.trafficThresholdGB),
            cutoffReference: String(saved.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB),
            accountName: saved.name || "",
            accountId: saved.id || ""
          }
        : {
            ak: "",
            sk: "",
            region: DEFAULT_CONFIG.regionId,
            ecsId: "",
            threshold: String(DEFAULT_CONFIG.trafficThresholdGB),
            cutoffReference: String(DEFAULT_CONFIG.vpsCutoffReferenceGB),
            accountName: "",
            accountId: ""
          }
    }
    setAk(target.ak)
    setSk(target.sk)
    setRegion(target.region)
    setEcsId(target.ecsId)
    setThreshold(target.threshold)
    setCutoffReference(target.cutoffReference)
    setAccountName(target.accountName)
    setAccountId(target.accountId)
    setSite(next)
    setErrorNotice(null)
    setSuccessNotice(null)
  }

  const handleSelectSite = async () => {
    if (typeof Dialog === "undefined" || !Dialog.actionSheet) {
      applySite(site === "intl" ? "cn" : "intl")
      return
    }
    const idx = await Dialog.actionSheet({
      title: "账号所属站点",
      message: "国际站账号的账单接口走新加坡入口，选错会导致余额和账单查询失败。",
      cancelButton: true,
      actions: [
        { label: `中国站 aliyun.com${site === "cn" ? " ✓" : ""}` },
        { label: `国际站 alibabacloud.com${site === "intl" ? " ✓" : ""}` }
      ]
    })
    if (idx === 0) applySite("cn")
    else if (idx === 1) applySite("intl")
  }

  const handleDelete = async () => {
    if (!onDelete || !accountId) return
    const label = accountDisplayName({ name: accountName, site })
    let confirmed = true
    if (typeof Dialog !== "undefined" && Dialog.confirm) {
      confirmed = await Dialog.confirm({
        title: `删除账号「${label}」？`,
        message: "只删除本机保存的凭据和设置，不影响阿里云账号本身。",
        cancelLabel: "取消",
        confirmLabel: "删除"
      } as any)
    }
    if (confirmed) onDelete(accountId)
  }

  const handleSave = () => {
    if (!ak.trim() || !sk.trim() || !ecsId.trim()) {
      setErrorNotice("请填写完整的 AccessKey ID、Secret 与 ECS 实例 ID！")
      return
    }
    const numThreshold = Number(threshold)
    if (!Number.isFinite(numThreshold) || numThreshold <= 0) {
      setErrorNotice("月流量额度参考必须是大于 0 的数字。")
      return
    }
    const numCutoffReference = Number(cutoffReference)
    if (!Number.isFinite(numCutoffReference) || numCutoffReference <= 0) {
      setErrorNotice("VPS 熔断参考线必须是大于 0 的数字。")
      return
    }
    const newCfg: AppConfig = {
      accessKeyId: ak.trim(),
      accessKeySecret: sk.trim(),
      regionId: region.trim() || "cn-hongkong",
      ecsInstanceId: ecsId.trim(),
      trafficThresholdGB: numThreshold,
      vpsCutoffReferenceGB: numCutoffReference,
      resetDayOfMonth: 1,
      id: accountId || newAccountId(),
      name: accountName.trim(),
      site
    }
    saveConfigToStorage(newCfg)
    onSave(newCfg)
  }

  const akRow = (
    <SettingsRow
      icon="key.fill"
      iconColor="systemOrange"
      title="AccessKey ID"
      detail={ak ? maskAccessKeyId(ak) : "未设置"}
      detailColor={ak ? "secondaryLabel" : "systemBlue"}
      accessibilityLabel="设置 AccessKey ID"
      action={() => promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (LTAI 开头)", ak, "LTAI...", setAk)}
    />
  )
  const skRow = (
    <SettingsRow
      icon="lock.fill"
      iconColor="systemRed"
      title="AccessKey Secret"
      detail={sk ? "已设置" : "未设置"}
      detailColor={sk ? "secondaryLabel" : "systemBlue"}
      accessibilityLabel="设置 AccessKey Secret"
      action={() => promptField("设置 AccessKey Secret", sk ? "已保存 Secret。输入新值将替换，留空则保持不变。" : "请输入阿里云 AccessKey Secret", sk, sk ? "留空保持不变" : "AccessKey Secret", setSk, true)}
    />
  )
  const ecsRow = (
    <SettingsRow
      icon="server.rack"
      iconColor="systemGreen"
      title="实例 ID"
      detail={ecsId || "未设置"}
      detailColor={ecsId ? "secondaryLabel" : "systemBlue"}
      accessibilityLabel="设置 ECS 实例 ID"
      action={() => promptField("设置 ECS 实例 ID", "请输入要监控状态的 ECS 实例 ID", ecsId, "i-xxxxxxxxxxxx", setEcsId)}
    />
  )
  const regionRow = (
    <SettingsRow
      icon="globe.asia.australia.fill"
      iconColor="systemIndigo"
      title="地域"
      detail={region || "cn-hongkong"}
      accessibilityLabel="设置 ECS 地域"
      action={handleSelectRegion}
    />
  )
  const thresholdRow = (
    <SettingsRow
      icon="speedometer"
      iconColor="systemPurple"
      title="月用量参考值"
      detail={`${threshold || "200"} GB`}
      accessibilityLabel="设置本地月用量参考值"
      action={() => promptField("本地月用量参考值 (GB)", "仅作本地用量参考，不代表阿里云账号完整免费额度余额，也不会触发 ECS 操作", threshold, "200", setThreshold)}
    />
  )
  const cutoffRow = (
    <SettingsRow
      icon="shield.lefthalf.filled"
      iconColor="systemTeal"
      title="VPS 熔断参考线"
      detail={`${cutoffReference} GB`}
      accessibilityLabel="设置 VPS 熔断参考线"
      action={() => promptField("VPS 熔断参考线 (GB)", "按 VPS 脚本阈值手动填写；此值只用于手机告警，不会同步或关机", cutoffReference, cutoffReference, setCutoffReference)}
    />
  )
  const nameRow = (
    <SettingsRow
      icon="person.crop.circle.fill"
      iconColor="systemBlue"
      title="账号名称"
      detail={accountName || accountDisplayName({ site })}
      detailColor={accountName ? "secondaryLabel" : "tertiaryLabel"}
      accessibilityLabel="设置账号名称"
      action={() => promptField("账号名称", "用于切换账号和小组件 Parameter，例如：国内、国外", accountName, site === "intl" ? "国外" : "国内", setAccountName)}
    />
  )
  const siteRow = (
    <SettingsRow
      icon="building.columns.fill"
      iconColor="systemTeal"
      title="站点"
      detail={siteLabel(site)}
      accessibilityLabel="设置账号站点"
      action={handleSelectSite}
    />
  )
  const deleteRow = onDelete && accountId && loadAccountProfiles<AppConfig>(DEFAULT_CONFIG).some(item => item.id === accountId) ? (
    <Button action={handleDelete} buttonStyle="plain" accessibilityLabel="删除此账号" frame={{ maxWidth: Infinity }}>
      <Text font="body" foregroundStyle="systemRed" padding={{ vertical: 2 }} frame={{ maxWidth: Infinity, alignment: "center" }}>
        删除此账号
      </Text>
    </Button>
  ) : null
  const pasteRow = (
    <Button action={handleSmartPaste} buttonStyle="plain" accessibilityLabel="一键识别剪贴板" frame={{ maxWidth: Infinity }}>
      <HStack alignment="center" spacing={12} padding={{ vertical: 2 }} frame={{ maxWidth: Infinity }}>
        <IconTile systemName="doc.on.clipboard.fill" color="systemBlue" size={29} />
        <Text font="body" foregroundStyle="systemBlue" frame={{ maxWidth: Infinity, alignment: "leading" }}>
          从剪贴板识别凭据
        </Text>
      </HStack>
    </Button>
  )
  const saveRow = (
    <Button action={handleSave} buttonStyle="plain" accessibilityLabel="保存配置并返回控制台" frame={{ maxWidth: Infinity }}>
      <Text font="body" fontWeight="semibold" foregroundStyle="systemBlue" padding={{ vertical: 2 }} frame={{ maxWidth: Infinity, alignment: "center" }}>
        保存并返回
      </Text>
    </Button>
  )
  const versionFooter = (
    <VStack alignment="center" spacing={2} frame={{ maxWidth: Infinity }}>
      <Text font="footnote" foregroundStyle="secondaryLabel">阿里云 CDT 监控 v{APP_VERSION}</Text>
      <Text font="caption1" foregroundStyle="tertiaryLabel">BSS 账单查询 · Build 2026.10.03</Text>
    </VStack>
  )
  const footnote = (text: string) => <Text font="footnote" foregroundStyle="secondaryLabel">{text}</Text>
  const toolbar = {
    topBarLeading: cancelable ?? isConfigReady(currentConfig)
      ? [
          <Button key="settings-back" action={onCancel} accessibilityLabel="返回">
            <Image systemName="chevron.backward" foregroundStyle="label" />
          </Button>,
        ]
      : undefined,
    topBarTrailing: [
      <Button key="settings-save" action={handleSave} accessibilityLabel="保存配置">
        <Text font="body" fontWeight="semibold" foregroundStyle="systemBlue">保存</Text>
      </Button>,
    ],
  }

  // Native grouped settings layout. The fallback below keeps the script
  // usable on older Scripting builds that do not expose List.
  if (typeof List !== "undefined") {
    return (
      <List
        navigationTitle="参数配置"
        navigationBarTitleDisplayMode="inline"
        toolbar={toolbar}
      >
        {errorNotice && (
          <Section>
            <SettingsNotice kind="error" text={errorNotice} />
          </Section>
        )}
        {successNotice && (
          <Section>
            <SettingsNotice kind="success" text={successNotice} />
          </Section>
        )}

        <Section
          header={<Text>账号</Text>}
          footer={footnote("名称会显示在切换菜单和小组件上。编辑小组件时在 Parameter 填名称可固定显示该账号，填「全部」显示所有账号。")}
        >
          {nameRow}
          {siteRow}
        </Section>

        <Section footer={footnote("复制包含阿里云凭据的文本后轻点，自动填入可识别的 AK、SK、实例 ID 与地域。")}>
          {pasteRow}
        </Section>

        <Section
          header={<Text>阿里云访问凭据</Text>}
          footer={footnote("凭据保存在 Scripting 本机 Storage，未做应用层加密，请使用最小权限 RAM 凭据。")}
        >
          {akRow}
          {skRow}
        </Section>

        <Section
          header={<Text>目标 ECS 实例</Text>}
          footer={footnote("Region ID 必须与 ECS 实例所在的物理地域一致。")}
        >
          {ecsRow}
          {regionRow}
        </Section>

        <Section
          header={<Text>流量参考值</Text>}
          footer={footnote("参考线仅用于本机展示和提醒，不代表阿里云账号完整免费额度，也不会控制 ECS。VPS 独立负责保活与熔断。")}
        >
          {thresholdRow}
          {cutoffRow}
        </Section>

        {deleteRow && <Section>{deleteRow}</Section>}

        <Section footer={versionFooter}>
          {saveRow}
        </Section>
      </List>
    )
  }

  return (
    <ScrollView
      background="systemGroupedBackground"
      showsIndicators={false}
      navigationTitle="参数配置"
      navigationBarTitleDisplayMode="inline"
      toolbar={toolbar}
    >
      <VStack alignment="leading" spacing={8} padding={{ horizontal: 16, top: 12, bottom: 40 }}>
        {(errorNotice || successNotice) && (
          <SettingsCard>
            {errorNotice && <SettingsCardRow><SettingsNotice kind="error" text={errorNotice} /></SettingsCardRow>}
            {successNotice && <SettingsCardRow><SettingsNotice kind="success" text={successNotice} /></SettingsCardRow>}
          </SettingsCard>
        )}

        <DashboardSectionHeader title="账号" />
        <SettingsCard>
          <SettingsCardRow>{nameRow}</SettingsCardRow>
          <Divider padding={{ leading: 57 }} />
          <SettingsCardRow>{siteRow}</SettingsCardRow>
        </SettingsCard>
        <SectionFootnote>编辑小组件时在 Parameter 填账号名称可固定显示该账号，填「全部」显示所有账号。</SectionFootnote>

        <SettingsCard>
          <SettingsCardRow>{pasteRow}</SettingsCardRow>
        </SettingsCard>
        <SectionFootnote>复制包含阿里云凭据的文本后轻点，自动填入可识别的 AK、SK、实例 ID 与地域。</SectionFootnote>

        <DashboardSectionHeader title="阿里云访问凭据" />
        <SettingsCard>
          <SettingsCardRow>{akRow}</SettingsCardRow>
          <Divider padding={{ leading: 57 }} />
          <SettingsCardRow>{skRow}</SettingsCardRow>
        </SettingsCard>
        <SectionFootnote>凭据保存在 Scripting 本机 Storage，未做应用层加密，请使用最小权限 RAM 凭据。</SectionFootnote>

        <DashboardSectionHeader title="目标 ECS 实例" />
        <SettingsCard>
          <SettingsCardRow>{ecsRow}</SettingsCardRow>
          <Divider padding={{ leading: 57 }} />
          <SettingsCardRow>{regionRow}</SettingsCardRow>
        </SettingsCard>
        <SectionFootnote>Region ID 必须与 ECS 实例所在的物理地域一致。</SectionFootnote>

        <DashboardSectionHeader title="流量参考值" />
        <SettingsCard>
          <SettingsCardRow>{thresholdRow}</SettingsCardRow>
          <Divider padding={{ leading: 57 }} />
          <SettingsCardRow>{cutoffRow}</SettingsCardRow>
        </SettingsCard>
        <SectionFootnote>参考线仅用于本机展示和提醒，不代表阿里云账号完整免费额度，也不会控制 ECS。VPS 独立负责保活与熔断。</SectionFootnote>

        <VStack padding={{ top: 20 }} spacing={16}>
          {deleteRow && (
            <SettingsCard>
              <SettingsCardRow>{deleteRow}</SettingsCardRow>
            </SettingsCard>
          )}
          <SettingsCard>
            <SettingsCardRow>{saveRow}</SettingsCardRow>
          </SettingsCard>
        </VStack>
        <VStack padding={{ top: 8 }}>{versionFooter}</VStack>
      </VStack>
    </ScrollView>
  )
}

// ==================== 7. 控制台仪表盘主视图 ====================

function restoreCachedMonitorData(raw: unknown, config: AppConfig): MonitorData | null {
  const cached = readSnapshot<MonitorData>(raw, config)
  if (!cached) return null
  const now = new Date()
  const thresholdGB = config.trafficThresholdGB > 0 ? config.trafficThresholdGB : DEFAULT_CONFIG.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB > 0 ? config.vpsCutoffReferenceGB : DEFAULT_CONFIG.vpsCutoffReferenceGB
  const remainingGB = Math.max(0, Number((thresholdGB - cached.totalGB).toFixed(2)))
  const { daysRemaining, monthTimeProgress } = chinaMonthProgress(now)
  const dailyUsage = readDailyUsage(config, now)
  return {
    ...cached,
    isCached: true,
    thresholdGB,
    vpsCutoffReferenceGB,
    remainingGB,
    percentage: usagePercentage(cached.totalGB, thresholdGB),
    daysRemaining,
    monthTimeProgress,
    dailyBudgetGB: (remainingGB / daysRemaining).toFixed(2),
    dailyUsage,
    sevenDayTotalGB: sumCompleteSevenDays(dailyUsage),
    todayEstimatedGB: dailyUsage[dailyUsage.length - 1]?.valueGB ?? null
  }
}

function getCachedDashboardSnapshot(config: AppConfig, key: string = SNAPSHOT_STORAGE_KEY): { data: MonitorData | null; lastUpdated: Date | null } {
  try {
    if (typeof Storage !== "undefined" && Storage?.get) {
      // 先读本账号快照；旧版未分账号的键仍可兜底，readSnapshot 会校验账号指纹。
      const scoped = Storage.get(scopedStorageKey(key, config))
      const raw = readSnapshot(scoped, config) ? scoped : Storage.get(key)
      if (raw) {
        const parsed = typeof raw === "string" ? JSON.parse(raw) : raw
        const data = restoreCachedMonitorData(parsed, config)
        return { data, lastUpdated: data?.updatedAt || null }
      }
    }
  } catch {}
  return { data: null, lastUpdated: null }
}

function AppDashboard() {
  const [config, setConfig] = useState<AppConfig>(loadSavedConfig())
  const [showSettings, setShowSettings] = useState(!isConfigReady(config))
  const [refreshGate] = useState(() => createRefreshGate())
  const initialCache = getCachedDashboardSnapshot(config)
  const [data, setData] = useState<MonitorData | null>(initialCache.data)
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(initialCache.lastUpdated)
  const financialBillPresentation = getMonthlyBillPresentation(data?.financialBill)
  const [isPrivacy, setIsPrivacy] = useState<boolean>(() => {
    try {
      return typeof Storage !== "undefined" && Storage.get(PRIVACY_STORAGE_KEY) === "true"
    } catch {
      return false
    }
  })
  const [isCopied, setIsCopied] = useState(false)
  const [accounts, setAccounts] = useState<AppConfig[]>(() => loadAccountProfiles<AppConfig>(DEFAULT_CONFIG))
  const [editingNew, setEditingNew] = useState<AppConfig | null>(null)

  const togglePrivacy = () => {
    const next = !isPrivacy
    setIsPrivacy(next)
    try {
      if (typeof Storage !== "undefined" && Storage?.set) {
        Storage.set(PRIVACY_STORAGE_KEY, String(next))
      }
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
    } catch {}
  }

  const handleCopyIp = () => {
    if (!data?.publicIp) return
    try {
      if (typeof Pasteboard !== "undefined" && (Pasteboard as any)?.setString) {
        ;(Pasteboard as any).setString(data.publicIp)
      }
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
      setIsCopied(true)
      setTimeout(() => setIsCopied(false), 1800)
    } catch {}
  }

  const handleShowEcsDaily = async () => {
    try {
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
    } catch {}

    const list = data?.financialBill?.ecsDailyList || []
    const total = data?.financialBillStatus !== "available"
      ? "不可用"
      : isPrivacy
        ? "****"
        : `${currencySymbol(data.financialBill?.currency)}${data.financialBill?.ecsAmount || "0.00"}`
    const lines = list.map(item => {
      const unavailable = item.available !== true
      const amt = unavailable ? "不可用" : isPrivacy ? "****" : `${currencySymbol(data?.financialBill?.currency)}${item.amount}`
      let tag = ""
      if (unavailable) {
        tag = " (查询不可用)"
      } else if (item.isToday) {
        tag = " (当日查询结果)"
      } else if (item.settled) {
        tag = " (查询返回记录)"
      } else {
        tag = " (未返回费用记录)"
      }
      return `${item.date}  ${amt}${tag}`
    })

    const msg = [
      `本月 ECS 产品账单查询结果: ${total}`,
      "说明：按账号维度汇总 ECS 产品费用，非当前配置的单台实例费用。",
      "",
      "【最近每日产品账单查询结果（可能延迟）】",
      lines.length > 0
        ? lines.join("\n")
        : data?.financialBillStatus === "available"
          ? "暂无每日产品账单数据"
          : "账单查询不可用",
      "",
      "注：账单按产品分类汇总，不能归因到当前 ECS 实例；月内数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({
        title: "ECS 费用明细",
        message: msg
      })
    }
  }

  const handleShowEipDaily = async () => {
    try {
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
    } catch {}

    const list = data?.financialBill?.eipDailyList || []
    const total = data?.financialBillStatus !== "available"
      ? "不可用"
      : isPrivacy
        ? "****"
        : `${currencySymbol(data.financialBill?.currency)}${data.financialBill?.eipAmount || "0.00"}`
    const lines = list.map(item => {
      const unavailable = item.available !== true
      const amt = unavailable ? "不可用" : isPrivacy ? "****" : `${currencySymbol(data?.financialBill?.currency)}${item.amount}`
      let tag = ""
      if (unavailable) {
        tag = " (查询不可用)"
      } else if (item.isToday) {
        tag = " (当日查询结果)"
      } else if (item.settled) {
        tag = " (查询返回记录)"
      } else {
        tag = " (未返回费用记录)"
      }
      return `${item.date}  ${amt}${tag}`
    })

    const msg = [
      `本月公网网络产品账单查询结果: ${total}`,
      "说明：按账号维度汇总公网网络产品费用，非当前配置公网 IP 的单独费用。",
      "",
      "【最近每日产品账单查询结果（可能延迟）】",
      lines.length > 0
        ? lines.join("\n")
        : data?.financialBillStatus === "available"
          ? "暂无每日产品账单数据"
          : "账单查询不可用",
      "",
      "注：账单按产品分类汇总，不能归因到当前公网 IP；月内数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({
        title: "公网网络费用明细",
        message: msg
      })
    }
  }

  const refresh = useCallback(
    async (cfg: AppConfig = config) => {
      const generation = refreshGate.start()
      if (!isConfigReady(cfg)) {
        setShowSettings(true)
        setLoading(false)
        return
      }
      setLoading(true)
      setErrorMsg(null)
      try {
        const res = await fetchMonitorData(cfg)
        if (!refreshGate.isCurrent(generation)) return
        assertSampleBillingMonth(res.updatedAt)
        res.dailyUsage = recordTrafficSample(cfg, res.totalGB, res.updatedAt)
        res.sevenDayTotalGB = sumCompleteSevenDays(res.dailyUsage)
        res.todayEstimatedGB = res.dailyUsage[res.dailyUsage.length - 1]?.valueGB ?? null
        res.isCached = false
        setData(res)
        setLastUpdated(res.updatedAt)
        try {
          if (typeof Storage !== "undefined" && Storage?.set) {
Storage.set(scopedStorageKey(SNAPSHOT_STORAGE_KEY, cfg), JSON.stringify(createSnapshot(cfg, res)))
            Storage.set(SNAPSHOT_STORAGE_KEY, JSON.stringify(createSnapshot(cfg, res)))
          }
        } catch {}
      } catch (e: any) {
        if (!refreshGate.isCurrent(generation)) return
        setErrorMsg(humanizeAliyunError(e?.message || "网络请求失败，请检查配置"))
        const cached = getCachedDashboardSnapshot(cfg)
        setData(cached.data)
        setLastUpdated(cached.lastUpdated)
      } finally {
        if (refreshGate.isCurrent(generation)) setLoading(false)
      }
    },
    [config, refreshGate]
  )

  useEffect(() => {
    if (isConfigReady(config)) {
      refresh(config)
    }
    return () => refreshGate.invalidate()
  }, [])

  const switchAccount = (next: AppConfig) => {
    refreshGate.invalidate()
    try {
      if (typeof Storage !== "undefined" && Storage?.set) Storage.set(STORAGE_KEY, JSON.stringify(next))
    } catch {}
    const cached = getCachedDashboardSnapshot(next)
    setEditingNew(null)
    setConfig(next)
    setData(cached.data)
    setLastUpdated(cached.lastUpdated)
    setErrorMsg(null)
    setIsCopied(false)
    setShowSettings(false)
    refresh(next)
  }

  const deleteAccount = (id: string) => {
    const remaining = removeAccountProfile(loadAccountProfiles<AppConfig>(DEFAULT_CONFIG), id)
    saveAccountProfiles(remaining)
    setAccounts(remaining)
    if (remaining.length > 0) {
      switchAccount(remaining[0])
      return
    }
    refreshGate.invalidate()
    try {
      if (typeof Storage !== "undefined" && Storage?.set) Storage.set(STORAGE_KEY, "")
    } catch {}
    setConfig({ ...DEFAULT_CONFIG })
    setData(null)
    setLastUpdated(null)
    setErrorMsg(null)
    setEditingNew(null)
    setShowSettings(true)
  }

  const startAddAccount = () => {
    setEditingNew({ ...DEFAULT_CONFIG, id: newAccountId(), site: accounts.some(item => item.site === "intl") ? "cn" : "intl" })
    setShowSettings(true)
  }

  // 账号切换：列出已保存账号，末尾提供「添加账号」。
  const handleSwitchAccount = async () => {
    const list = loadAccountProfiles<AppConfig>(DEFAULT_CONFIG)
    setAccounts(list)
    if (typeof Dialog === "undefined" || !Dialog.actionSheet) {
      startAddAccount()
      return
    }
    const actions = list.map((item, index) => ({
      label: `${accountDisplayName(item, index)} · ${siteLabel(item.site)}${item.id === config.id ? " ✓" : ""}`
    }))
    actions.push({ label: "添加账号…" })
    const idx = await Dialog.actionSheet({
      title: "切换阿里云账号",
      message: "小组件可在「编辑小组件 → Parameter」填账号名称固定显示，填「全部」同时显示所有账号。",
      cancelButton: true,
      actions
    })
    if (idx === null || idx === undefined || idx < 0) return
    if (idx === list.length) {
      startAddAccount()
    } else if (list[idx] && list[idx].id !== config.id) {
      switchAccount(list[idx])
    }
  }

  if (showSettings) {
    return (
      <NavigationStack>
        <SettingsComponent
          key={(editingNew || config).id || "default"}
          currentConfig={editingNew || config}
          cancelable={editingNew ? isConfigReady(config) : undefined}
          onSave={newCfg => {
            refreshGate.invalidate()
            const cached = getCachedDashboardSnapshot(newCfg)
            setAccounts(loadAccountProfiles<AppConfig>(DEFAULT_CONFIG))
            setEditingNew(null)
            setConfig(newCfg)
            setData(cached.data)
            setLastUpdated(cached.lastUpdated)
            setErrorMsg(null)
            setIsCopied(false)
            setShowSettings(false)
            refresh(newCfg)
          }}
          onDelete={editingNew || accounts.length === 0 ? undefined : deleteAccount}
          onCancel={() => {
            setEditingNew(null)
            setShowSettings(!isConfigReady(config))
          }}
        />
      </NavigationStack>
    )
  }

  const isRunning = data?.ecsStatus === "Running"
  const isStarting = data?.ecsStatus === "Starting"
  const isStopping = data?.ecsStatus === "Stopping"
  const isTransitional = isStarting || isStopping
  const isStopped = data?.ecsStatus === "Stopped"

  const statusColor = isRunning
    ? "systemGreen"
    : isTransitional
      ? "systemOrange"
      : isStopped
        ? "secondaryLabel"
        : errorMsg && !data
          ? "systemRed"
          : "secondaryLabel"

  const balanceColor = !data?.financialBalance
    ? "secondaryLabel"
    : data.financialBalance.status === "sufficient"
      ? "systemGreen"
      : data.financialBalance.status === "low"
        ? "systemOrange"
        : "systemRed"

  const observedStatusLabel = loading && !data
    ? "同步中"
    : data?.ecsStatus === "Running"
      ? "运行中"
      : data?.ecsStatus === "Stopped"
        ? "已停止"
        : data?.ecsStatus === "Starting"
          ? "启动中"
          : data?.ecsStatus === "Stopping"
            ? "停止中"
            : data?.ecsStatus === "Unknown"
              ? "状态未知"
              : errorMsg
                ? "同步失败"
                : "等待同步"
  const statusLabel = data?.isCached ? `${observedStatusLabel}（缓存）` : observedStatusLabel
  const publicIpLabel = loading
    ? "获取中..."
    : errorMsg && !data
      ? "获取失败，点击刷新"
      : data?.publicIp || (data ? "未绑定公网 IP" : "等待同步")
  const publicIpColor = data?.publicIp ? "systemBlue" : errorMsg && !data ? "systemRed" : "secondaryLabel"

  const now = new Date()
  const monthTimeProgress = data?.monthTimeProgress ?? chinaMonthProgress(now).monthTimeProgress
  const healthMeta = data
    ? getTrafficHealthMeta(data.totalGB, data.vpsCutoffReferenceGB, data.percentage, monthTimeProgress)
    : null

  return (
    <NavigationStack>
      <ZStack
        frame={{ maxWidth: Infinity, maxHeight: Infinity }}
        navigationTitle={accounts.length > 1
          ? accountDisplayName(config, Math.max(0, accounts.findIndex(item => item.id === config.id)))
          : "阿里云 CDT"}
        navigationBarTitleDisplayMode="large"
        toolbar={{
          topBarLeading: [
            <Button key="dashboard-accounts" action={handleSwitchAccount} accessibilityLabel="切换账号">
              <Image systemName={accounts.length > 1 ? "person.2" : "person.crop.circle.badge.plus"} foregroundStyle="label" />
            </Button>,
          ],
          topBarTrailing: [
            <Button key="dashboard-refresh" action={() => refresh(config)} disabled={loading} accessibilityLabel="刷新数据">
              <Image systemName="arrow.clockwise" foregroundStyle="label" />
            </Button>,
            <Button key="dashboard-settings" action={() => setShowSettings(true)} accessibilityLabel="设置">
              <Image systemName="gearshape" foregroundStyle="label" />
            </Button>,
          ],
        }}
      >
        <ScrollView background="systemGroupedBackground" showsIndicators={false} safeAreaPadding={{ bottom: true }}>
          <VStack alignment="leading" spacing={8} padding={{ horizontal: 16, top: 8, bottom: 20 }}>
            {errorMsg && (
              <HStack alignment="top" spacing={10} padding={{ horizontal: 16, vertical: 12 }} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface(16)}>
                <Image systemName="exclamationmark.triangle.fill" font={15} foregroundStyle="systemRed" />
                <Text font="subheadline" foregroundStyle="label" lineLimit={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                  {errorMsg}
                </Text>
              </HStack>
            )}

            {/* 本月出网流量主卡片 */}
            <VStack alignment="leading" spacing={12} padding={{ horizontal: 18, vertical: 16 }} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface(22)}>
              <HStack alignment="center">
                <Text font="subheadline" fontWeight="semibold" foregroundStyle="label">本月出网流量</Text>
                <Spacer />
                <Text font="footnote" monospacedDigit foregroundStyle="secondaryLabel">
                  {loading
                    ? "正在更新…"
                    : lastUpdated
                      ? `${data?.isCached ? "缓存 · " : ""}${String(lastUpdated.getHours()).padStart(2, "0")}:${String(lastUpdated.getMinutes()).padStart(2, "0")} 更新`
                      : "等待同步"}
                </Text>
              </HStack>
              <HStack alignment="lastTextBaseline" spacing={4}>
                <Text font={44} fontWeight="bold" monospacedDigit foregroundStyle="label" lineLimit={1} minScaleFactor={0.6}>
                  {data ? data.totalGB.toFixed(2) : "--"}
                </Text>
                <Text font="title3" fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
                <Spacer />
                <Text font="subheadline" monospacedDigit foregroundStyle="secondaryLabel">
                  / {data?.thresholdGB ?? config.trafficThresholdGB} GB
                </Text>
              </HStack>
              <ProgressView
                progressViewStyle="linear"
                value={data ? Math.max(0, Math.min(1, data.percentage / 100)) : 0}
                total={1}
                tint={data && data.percentage >= 100 ? "systemOrange" : "systemBlue"}
                frame={{ maxWidth: Infinity }}
              />
            </VStack>

            {/* Section 1: ECS 实例状态 */}
            <DashboardSectionHeader title="实例" detail={config.regionId} />
            <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
              <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12}>
                <IconTile systemName="server.rack" color="systemGreen" />
                <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                  <Text font="body" foregroundStyle="label">ECS 云服务器</Text>
                  <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>{config.ecsInstanceId}</Text>
                </VStack>
                <HStack spacing={6} alignment="center">
                  <Circle fill={statusColor} frame={{ width: 8, height: 8 }} />
                  <Text font="subheadline" foregroundStyle="secondaryLabel">{statusLabel}</Text>
                </HStack>
              </HStack>

              <Divider padding={{ leading: 58 }} />

              <Button action={handleCopyIp} buttonStyle="plain" accessibilityLabel="复制公网 IP 地址">
                <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12}>
                  <IconTile systemName={isCopied ? "checkmark" : "network"} color={isCopied ? "systemGreen" : "systemBlue"} />
                  <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                    <Text font="body" foregroundStyle="label">公网 IP 地址</Text>
                    <Text font="footnote" monospacedDigit foregroundStyle={isCopied ? "systemGreen" : publicIpColor === "systemBlue" ? "secondaryLabel" : publicIpColor} lineLimit={1}>
                      {isCopied ? "已复制到剪贴板" : publicIpLabel}
                    </Text>
                  </VStack>
                  <Image systemName={isCopied ? "checkmark.circle.fill" : "doc.on.doc"} font={15} foregroundStyle={isCopied ? "systemGreen" : "systemBlue"} />
                </HStack>
              </Button>
            </VStack>
            <SectionFootnote>状态来自阿里云只读查询；开关机与熔断由 VPS 脚本独立负责。</SectionFootnote>

            {/* Section 2: 账户与费用 */}
            {data && (
              <>
                <DashboardSectionHeader
                  title="账户与费用"
                  trailing={
                    <Button action={togglePrivacy} buttonStyle="plain" accessibilityLabel={isPrivacy ? "显示金额" : "隐藏金额"}>
                      <HStack spacing={4} alignment="center">
                        <Image systemName={isPrivacy ? "eye.slash" : "eye"} font={13} foregroundStyle="systemBlue" />
                        <Text font="footnote" foregroundStyle="systemBlue">{isPrivacy ? "显示" : "隐藏"}</Text>
                      </HStack>
                    </Button>
                  }
                />
                <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
                  <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="top">
                    <VStack alignment="leading" spacing={4} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                      <Text font="footnote" foregroundStyle="secondaryLabel">账户现金余额</Text>
                      <HStack alignment="lastTextBaseline" spacing={3}>
                        {data.financialBalance && (
                          <Text font="headline" foregroundStyle={data.financialBalance.status === "arrears" ? "systemRed" : "label"}>
                            {currencySymbol(data.financialBalance.currency)}
                          </Text>
                        )}
                        <Text font={26} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle={!data.financialBalance ? "secondaryLabel" : data.financialBalance.status === "arrears" ? "systemRed" : "label"}>
                          {!data.financialBalance ? "不可用" : isPrivacy ? "****" : data.financialBalance.availableCashAmount}
                        </Text>
                      </HStack>
                      <HStack spacing={4} alignment="center">
                        <Circle fill={balanceColor} frame={{ width: 6, height: 6 }} />
                        <Text font="caption1" foregroundStyle={balanceColor}>
                          {!data.financialBalance
                            ? "余额查询不可用"
                            : data.financialBalance.status === "sufficient"
                              ? "资金充足"
                              : data.financialBalance.status === "low"
                                ? "余额偏低"
                                : "已欠费"}
                        </Text>
                      </HStack>
                    </VStack>

                    <Divider frame={{ height: 56 }} />

                    <VStack alignment="leading" spacing={4} padding={{ leading: 16 }} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                      <Text font="footnote" foregroundStyle="secondaryLabel">{financialBillPresentation.label}</Text>
                      <HStack alignment="lastTextBaseline" spacing={3}>
                        {data.financialBillStatus === "available" && (
                          <Text font="headline" foregroundStyle="label">{currencySymbol(data.financialBill?.currency)}</Text>
                        )}
                        <Text font={26} fontWeight="bold" monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle={data.financialBillStatus !== "available" ? "secondaryLabel" : "label"}>
                          {data.financialBillStatus !== "available"
                            ? "不可用"
                            : isPrivacy
                              ? "****"
                              : data.financialBill?.paymentAmount || "0.00"}
                        </Text>
                      </HStack>
                      <Text font="caption1" lineLimit={2} foregroundStyle={data.financialBillStatus !== "available" ? "secondaryLabel" : data.financialBill && parseFloat(data.financialBill.paymentAmount) > 0 ? "systemOrange" : "systemGreen"}>
                        {data.financialBillStatus !== "available" ? "账单查询不可用" : financialBillPresentation.detail}
                      </Text>
                    </VStack>
                  </HStack>

                  <Divider padding={{ leading: 16 }} />

                  <Button action={handleShowEcsDaily} buttonStyle="plain" accessibilityLabel="查看 ECS 产品每日费用明细" frame={{ maxWidth: Infinity }}>
                    <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12} frame={{ maxWidth: Infinity }}>
                      <IconTile systemName="server.rack" color="systemBlue" />
                      <Text font="body" foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>ECS 产品</Text>
                      <Text font="body" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                        {data.financialBillStatus !== "available" ? "不可用" : isPrivacy ? "****" : `${currencySymbol(data.financialBill?.currency)}${data.financialBill?.ecsAmount || "0.00"}`}
                      </Text>
                      <Image systemName="chevron.right" font={13} fontWeight="semibold" foregroundStyle="tertiaryLabel" />
                    </HStack>
                  </Button>

                  <Divider padding={{ leading: 58 }} />

                  <Button action={handleShowEipDaily} buttonStyle="plain" accessibilityLabel="查看公网网络产品每日费用明细" frame={{ maxWidth: Infinity }}>
                    <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12} frame={{ maxWidth: Infinity }}>
                      <IconTile systemName="globe.asia.australia" color="systemIndigo" />
                      <Text font="body" foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>公网网络</Text>
                      <Text font="body" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                        {data.financialBillStatus !== "available" ? "不可用" : isPrivacy ? "****" : `${currencySymbol(data.financialBill?.currency)}${data.financialBill?.eipAmount || "0.00"}`}
                      </Text>
                      <Image systemName="chevron.right" font={13} fontWeight="semibold" foregroundStyle="tertiaryLabel" />
                    </HStack>
                  </Button>
                </VStack>
                <SectionFootnote>轻触产品行查看最近每日账单分类；结果按账号汇总，非单实例或单 IP 费用。</SectionFootnote>
              </>
            )}

            {/* Section 3: 用量详情 */}
            <DashboardSectionHeader title="用量详情" detail={data ? `已用 ${data.percentage.toFixed(1)}%` : undefined} />
            <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
              {data && healthMeta && (
                <>
                  <HStack spacing={12} alignment="center" padding={{ horizontal: 16, vertical: 11 }}>
                    <IconTile systemName={healthMeta.icon.replace(/\.(circle|octagon)\.fill$/, "")} color={healthMeta.color} />
                    <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                      <Text font="body" foregroundStyle="label" lineLimit={2}>{healthMeta.label}</Text>
                      <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1} minScaleFactor={0.8}>
                        本月时间已过 {monthTimeProgress.toFixed(0)}% · 流量已用 {data.percentage.toFixed(1)}% · VPS 线余 {Math.max(0, data.vpsCutoffReferenceGB - data.totalGB).toFixed(1)} GB
                      </Text>
                    </VStack>
                  </HStack>
                  <Divider padding={{ leading: 58 }} />
                </>
              )}
              {data ? (
                <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={0}>
                  <UsageMetric
                    label={data.totalGB > data.thresholdGB ? "超出参考值" : "参考余量"}
                    value={data.totalGB > data.thresholdGB ? `+${(data.totalGB - data.thresholdGB).toFixed(1)}` : data.remainingGB.toFixed(1)}
                    unit="GB"
                    color={data.totalGB > data.thresholdGB ? "systemRed" : "label"}
                  />
                  <Divider frame={{ height: 36 }} />
                  <UsageMetric label="距结算" value={String(data.daysRemaining)} unit="天" />
                  <Divider frame={{ height: 36 }} />
                  <UsageMetric label="日均可用" value={data.dailyBudgetGB} unit="GB" />
                </HStack>
              ) : (
                <HStack padding={16} alignment="center">
                  <Text font="footnote" foregroundStyle="secondaryLabel">正在同步阿里云最新用量数据...</Text>
                </HStack>
              )}
            </VStack>
            <SectionFootnote>VPS 独立负责保活与熔断；手机只展示 CDT 用量和账单查询结果。</SectionFootnote>

            <Text font="caption1" foregroundStyle="tertiaryLabel" frame={{ maxWidth: Infinity, alignment: "center" }} padding={{ top: 12 }}>
              Aliyun CDT Monitor v{APP_VERSION}
            </Text>
          </VStack>
        </ScrollView>
      </ZStack>
    </NavigationStack>
  )
}

// ==================== 8. 执行分流 (Widget 还是 App) ====================

async function main() {
  const isWidget = typeof Widget !== "undefined" && Boolean(Widget?.family)

  if (isWidget) {
    const accounts = loadAccountProfiles<AppConfig>(DEFAULT_CONFIG)
    if (accounts.length === 0) {
      presentWidget(<NotConfiguredWidget />)
      return
    }
    // 长按小组件 → 编辑小组件 → Parameter：留空/国内/国外/账号名/序号/全部
    const selection = selectWidgetAccounts(accounts, (Widget as any)?.parameter, loadSavedConfig().id)
    const nameOf = (cfg: AppConfig) => accountDisplayName(cfg, accounts.indexOf(cfg))

    const loadOne = async (config: AppConfig): Promise<MonitorData> => {
      const data = await fetchMonitorData(config, false)
      assertSampleBillingMonth(data.updatedAt)
      data.dailyUsage = recordTrafficSample(config, data.totalGB, data.updatedAt)
      data.sevenDayTotalGB = sumCompleteSevenDays(data.dailyUsage)
      data.todayEstimatedGB = data.dailyUsage[data.dailyUsage.length - 1]?.valueGB ?? null
      try {
        if (typeof Storage !== "undefined" && Storage?.set) {
          const key = scopedStorageKey(WIDGET_SNAPSHOT_STORAGE_KEY, config)
          const previous = readSnapshot<MonitorData>(Storage.get(key), config)
          if (!previous || previous.updatedAt.getTime() < data.updatedAt.getTime()) {
            Storage.set(key, JSON.stringify(createSnapshot(config, data)))
          }
        }
      } catch {}
      return data
    }
    // 弱网容灾：尝试降级渲染本地持久化快照，避免组件变红
    const cachedOne = (config: AppConfig): MonitorData | null => {
      try {
        for (const key of [WIDGET_SNAPSHOT_STORAGE_KEY, SNAPSHOT_STORAGE_KEY]) {
          const cached = getCachedDashboardSnapshot(config, key).data
          if (cached) return cached
        }
      } catch {}
      return null
    }
    const errorView = (title: string, message: string) => Widget.family === "accessoryInline"
      ? <Text lineLimit={1}>CDT {title}</Text>
      : (
        <VStack
          alignment="leading"
          spacing={6}
          padding={{ horizontal: 14, vertical: 12 }}
          widgetBackground="systemBackground"
          frame={{ maxWidth: Infinity, maxHeight: Infinity }}
        >
          <HStack spacing={6} alignment="center">
            <Image systemName="exclamationmark.triangle.fill" font={13} foregroundStyle="systemRed" />
            <Text font="caption1" bold foregroundStyle="systemRed" lineLimit={1}>
              {title}
            </Text>
          </HStack>
          <Text font="caption2" foregroundStyle="secondaryLabel" lineLimit={4}>
            {message}
          </Text>
        </VStack>
      )

    if (selection.accounts.length === 0) {
      const names = accounts.map(nameOf).join("、")
      presentWidget(errorView(`未找到账号「${selection.unmatched}」`, `Parameter 可填：${names}、全部；留空显示 App 当前账号。`))
      return
    }

    if (selection.mode === "all") {
      const items: AccountWidgetItem[] = await Promise.all(selection.accounts.map(async config => {
        try {
          return { name: nameOf(config), site: config.site, data: await loadOne(config) }
        } catch (err: any) {
          const cached = cachedOne(config)
          return { name: nameOf(config), site: config.site, data: cached, error: cached ? undefined : widgetErrorHint(err?.message) }
        }
      }))
      if (Widget.family === "accessoryInline") {
        presentWidget(
          <Text lineLimit={1} monospacedDigit>
            {items.map(item => item.data ? `${item.name} ${item.data.totalGB.toFixed(1)}/${item.data.thresholdGB}G` : `${item.name} 失败`).join(" · ")}
          </Text>
        )
      } else if (Widget.family === "accessoryCircular" || Widget.family === "accessoryRectangular") {
        const first = items.find(item => item.data)
        if (first?.data) presentMonitorWidget({ ...(first.data as MonitorData), accountName: first.name })
        else presentWidget(errorView("获取失败", items[0]?.error || "请稍后重试"))
      } else {
        presentWidget(<MultiAccountWidgetView items={items} family={Widget.family} />)
      }
      return
    }

    const config = selection.accounts[0]
    const accountName = accounts.length > 1 ? nameOf(config) : undefined
    try {
      const data = await loadOne(config)
      data.accountName = accountName
      presentMonitorWidget(data)
    } catch (err: any) {
      console.error("小组件加载失败:", err)
      const cached = cachedOne(config)
      if (cached) {
        cached.accountName = accountName
        presentMonitorWidget(cached)
        return
      }
      presentWidget(errorView(accountName ? `${accountName} 获取失败` : "获取失败", widgetErrorHint(err?.message)))
    }
  } else {
    await Navigation.present({
      element: <AppDashboard />
    })
    Script.exit()
  }
}

main()
