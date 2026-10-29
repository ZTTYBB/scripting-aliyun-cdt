export interface ConfigIdentityCfg {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  vpsCutoffReferenceGB: number
  resetDayOfMonth: number
}

export interface DailyUsagePoint {
  date: string
  label: string
  valueGB: number | null
  isToday: boolean
}

export interface MonitorSnapshot<T> {
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

export interface ChinaDateParts {
  year: number
  month: number
  day: number
  weekday: number
}

// Aliyun billing cycles follow China Standard Time (UTC+8, no DST), regardless of the device time zone.
export function chinaDateParts(date: Date): ChinaDateParts {
  const shifted = new Date(date.getTime() + RUNTIME_CHINA_OFFSET_MS)
  return {
    year: shifted.getUTCFullYear(),
    month: shifted.getUTCMonth() + 1,
    day: shifted.getUTCDate(),
    weekday: shifted.getUTCDay()
  }
}

export function chinaMonthKey(date: Date, monthOffset = 0): string {
  const parts = chinaDateParts(date)
  const target = new Date(Date.UTC(parts.year, parts.month - 1 + monthOffset, 1))
  return `${target.getUTCFullYear()}-${String(target.getUTCMonth() + 1).padStart(2, "0")}`
}

export function chinaMonthProgress(date: Date): {
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

export function usagePercentage(totalGB: number, thresholdGB: number): number {
  if (!Number.isFinite(totalGB) || !Number.isFinite(thresholdGB) || thresholdGB <= 0) return 0
  return Math.max(0, Number(((totalGB / thresholdGB) * 100).toFixed(1)))
}

export type NormalizedEcsStatus = "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"

export function normalizeEcsStatus(value: unknown): NormalizedEcsStatus {
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
export function aliyunHttpError(action: string, status: number, body: string): Error {
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

export function widgetErrorHint(message: unknown): string {
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

export function configScope(config: ConfigIdentityCfg): string {
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

export function accountHistoryScope(config: ConfigIdentityCfg): string {
  return runtimeFingerprint(JSON.stringify([config.accessKeyId.trim(), "cdt"]))
}

export async function withRequestTimeout<T>(
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

export function createSnapshot<T extends { totalGB: number; updatedAt?: unknown }>(
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

export function readSnapshot<T = any>(
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

export function createRefreshGate() {
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

export function assertSampleBillingMonth(sampledAt: Date, now: Date = new Date()): void {
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

export function recordTrafficSample(
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

export function readDailyUsage(config: ConfigIdentityCfg, now: Date = new Date()): DailyUsagePoint[] {
  return runtimeBuildDailyUsage(runtimeLoadHistory(config, now).snapshots, now)
}

export function sumCompleteSevenDays(points: DailyUsagePoint[]): number | null {
  if (points.length !== 7 || points.some(point => point.valueGB === null || !Number.isFinite(point.valueGB) || point.valueGB < 0)) {
    return null
  }
  return Number(points.reduce((sum, point) => sum + point.valueGB!, 0).toFixed(2))
}
