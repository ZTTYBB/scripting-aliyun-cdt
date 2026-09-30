/**
 * ============================================================================
 * 阿里云 CDT 流量监控与 ECS 智控【桌面小组件专属脚本】
 * 文件名: widget.tsx
 * ============================================================================
 * 通用版特性：
 * 1. 自动从 Scripting Storage 读取用户配置，绝无硬编码凭据
 * 2. 若用户尚未配置，小组件优雅提示用户在 App 内打开脚本进行配置
 * 3. 兼容 iOS 16+ 主屏幕（小号/中号/大号）及锁屏小组件
 * 4. 纯 TS 内置 HMAC-SHA1 签名与 POP API 客户端
 */

import {
  Widget,
  VStack,
  HStack,
  ZStack,
  Text,
  Image,
  Spacer,
  Circle,
  Divider,
  ProgressView
} from "scripting"

const WIDGET_TRACK = {
  light: "rgba(142, 142, 147, 0.18)",
  dark: "rgba(142, 142, 147, 0.36)"
} as any

const WIDGET_PANEL = {
  light: "rgba(255, 255, 255, 0.72)",
  dark: "rgba(118, 118, 128, 0.24)"
} as any

const WIDGET_SECONDARY = {
  light: "rgba(60, 60, 67, 0.62)",
  dark: "rgba(235, 235, 245, 0.68)"
} as any

const WIDGET_TERTIARY = {
  light: "rgba(60, 60, 67, 0.42)",
  dark: "rgba(235, 235, 245, 0.48)"
} as any

// ==================== 1. 本地存储配置读取 ====================

interface AppConfig {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  vpsCutoffReferenceGB: number
  resetDayOfMonth: number
}

const STORAGE_KEY = "aliyun_cdt_monitor_config"
const TRAFFIC_HISTORY_KEY = "aliyun_cdt_daily_history_v1"
const DASHBOARD_SNAPSHOT_STORAGE_KEY = "aliyun_cdt_dashboard_cache"
const WIDGET_REFRESH_AFTER_MS = 15 * 60 * 1000

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
        return { ...DEFAULT_CONFIG, ...parsed }
      }
    }
  } catch (e) {
    console.error("读取本地配置失败:", e)
  }
  return { ...DEFAULT_CONFIG }
}

function isConfigReady(cfg: AppConfig): boolean {
  return (
    Boolean(cfg.accessKeyId?.trim()) &&
    Boolean(cfg.accessKeySecret?.trim()) &&
    Boolean(cfg.ecsInstanceId?.trim())
  )
}

interface TrafficSnapshot {
  date: string
  totalGB: number
  updatedAt: number
}

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

interface TrafficHistory {
  version: 1
  scope: string
  month: string
  snapshots: TrafficSnapshot[]
}

interface DailyUsagePoint {
  date: string
  label: string
  valueGB: number | null
  isToday: boolean
}

function localDateKey(date: Date): string {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, "0")
  const day = String(date.getDate()).padStart(2, "0")
  return `${year}-${month}-${day}`
}

function offsetDate(date: Date, dayOffset: number): Date {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate() + dayOffset)
}

function historyScope(config: AppConfig): string {
  const source = `${config.accessKeyId.trim()}|cdt`
  let hash = 2166136261
  for (let i = 0; i < source.length; i++) {
    hash ^= source.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0).toString(36)
}

function loadTrafficHistory(): TrafficHistory | null {
  try {
    const saved = Storage.get(TRAFFIC_HISTORY_KEY)
    if (!saved) return null
    const parsed = typeof saved === "string" ? JSON.parse(saved) : saved
    if (parsed?.version !== 1 || !Array.isArray(parsed?.snapshots)) return null
    return parsed as TrafficHistory
  } catch (error) {
    console.error("读取流量历史失败:", error)
    return null
  }
}

function buildDailyUsage(config: AppConfig, totalGB: number, now: Date): DailyUsagePoint[] {
  const today = localDateKey(now)
  const month = today.slice(0, 7)
  const scope = historyScope(config)
  let history = loadTrafficHistory()

  if (history?.scope !== scope || history?.month !== month) {
    history = { version: 1, scope, month, snapshots: [] }
  }

  const snapshots = history.snapshots
    .filter(item => item?.date?.startsWith(month) && Number.isFinite(item?.totalGB))
    .sort((a, b) => a.date.localeCompare(b.date))
  const latestSnapshot = snapshots[snapshots.length - 1]

  // 月累计值下降通常代表账期重置或接口口径变化，旧基线不能继续使用。
  if (latestSnapshot && totalGB + 0.005 < latestSnapshot.totalGB) {
    snapshots.length = 0
  }

  const todaySnapshot = snapshots.find(item => item.date === today)
  if (todaySnapshot) {
    todaySnapshot.totalGB = totalGB
    todaySnapshot.updatedAt = now.getTime()
  } else {
    snapshots.push({ date: today, totalGB, updatedAt: now.getTime() })
  }

  history.snapshots = snapshots.slice(-32)
  try {
    Storage.set(TRAFFIC_HISTORY_KEY, JSON.stringify(history))
  } catch (error) {
    console.error("保存流量历史失败:", error)
  }

  const byDate = new Map(history.snapshots.map(item => [item.date, item]))
  const weekdayLabels = ["日", "一", "二", "三", "四", "五", "六"]

  return Array.from({ length: 7 }, (_, index) => {
    const date = offsetDate(now, index - 6)
    const dateKey = localDateKey(date)
    const previousKey = localDateKey(offsetDate(date, -1))
    const current = byDate.get(dateKey)
    const previous = byDate.get(previousKey)
    let valueGB: number | null = null

    if (current && previous && current.totalGB + 0.005 >= previous.totalGB) {
      valueGB = Math.max(0, Number((current.totalGB - previous.totalGB).toFixed(2)))
    }

    return {
      date: dateKey,
      label: index === 6 ? "今" : weekdayLabels[date.getDay()],
      valueGB,
      isToday: index === 6
    }
  })
}

// ==================== 2. 纯 TS HMAC-SHA1 与 POP 签名算法 ====================

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

  const response = await fetch(requestUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: bodyString
  })

  if (!response.ok) {
    const err = await response.text()
    throw new Error(`Aliyun [${action}] 错误 (${response.status}): ${err}`)
  }

  return (await response.json()) as T
}

// ==================== 3. 业务数据模型 ====================

interface WidgetData {
  totalGB: number
  thresholdGB: number
  vpsCutoffReferenceGB: number
  cutoffRemainingGB: number
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  dailyUsage: DailyUsagePoint[]
  sevenDayTotalGB: number | null
  todayEstimatedGB: number | null
  updatedAt: Date
  ecsStatus: "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"
  publicIp?: string
  color: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value)
}

function parseCachedDate(value: unknown): Date | null {
  if (value instanceof Date) {
    return Number.isFinite(value.getTime()) ? value : null
  }
  if (typeof value !== "string" && typeof value !== "number") return null
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date : null
}

function normalizeEcsStatus(value: unknown): WidgetData["ecsStatus"] {
  switch (value) {
    case "Running":
    case "Stopped":
    case "Starting":
    case "Stopping":
      return value
    default:
      return "Unknown"
  }
}

function buildUnavailableDailyUsage(now: Date): DailyUsagePoint[] {
  const weekdayLabels = ["日", "一", "二", "三", "四", "五", "六"]

  return Array.from({ length: 7 }, (_, index) => {
    const date = offsetDate(now, index - 6)
    return {
      date: localDateKey(date),
      label: index === 6 ? "今" : weekdayLabels[date.getDay()],
      valueGB: null,
      isToday: index === 6
    }
  })
}

/**
 * The app dashboard stores ConsoleData, which intentionally has no local
 * sampling series. Validate its stable source fields before adapting it for a
 * widget fallback; never pass an untyped Storage value into a widget view.
 */
function adaptDashboardSnapshotForWidget(raw: unknown): WidgetData | null {
  if (!isRecord(raw)) return null

  const totalGB = raw.totalGB
  const thresholdGB = raw.thresholdGB
  const vpsCutoffReferenceGB = raw.vpsCutoffReferenceGB
  const updatedAt = parseCachedDate(raw.updatedAt)

  if (
    !isFiniteNumber(totalGB) || totalGB < 0 ||
    !isFiniteNumber(thresholdGB) || thresholdGB <= 0 ||
    !isFiniteNumber(vpsCutoffReferenceGB) || vpsCutoffReferenceGB <= 0 ||
    !updatedAt
  ) {
    return null
  }

  const cachedDaysRemaining = raw.daysRemaining
  const daysRemaining = isFiniteNumber(cachedDaysRemaining) && cachedDaysRemaining >= 1
    ? Math.max(1, Math.round(cachedDaysRemaining))
    : Math.max(1, new Date(updatedAt.getFullYear(), updatedAt.getMonth() + 1, 0).getDate() - updatedAt.getDate() + 1)
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))
  const color = totalGB >= vpsCutoffReferenceGB
    ? "systemRed"
    : totalGB >= vpsCutoffReferenceGB - 15
      ? "systemOrange"
      : "systemGreen"
  const publicIp = typeof raw.publicIp === "string" && raw.publicIp.trim()
    ? raw.publicIp.trim()
    : undefined

  return {
    totalGB,
    thresholdGB,
    vpsCutoffReferenceGB,
    cutoffRemainingGB,
    remainingGB,
    percentage,
    daysRemaining,
    dailyBudgetGB: (remainingGB / daysRemaining).toFixed(2),
    // The dashboard does not save local daily samples, so these remain unknown.
    dailyUsage: buildUnavailableDailyUsage(updatedAt),
    sevenDayTotalGB: null,
    todayEstimatedGB: null,
    updatedAt,
    ecsStatus: normalizeEcsStatus(raw.ecsStatus),
    publicIp,
    color
  }
}

async function fetchWidgetData(config: AppConfig): Promise<WidgetData> {
  // 1. 查询 CDT 流量
  const cdtData = await aliyunRequest<{
    TrafficDetails?: Array<{ Traffic?: number }>
  }>("cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config)

  const details = cdtData.TrafficDetails || []
  const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB || 195
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))

  // 2. 查询 ECS 状态；失败时仍保留已成功获取的 CDT 用量。
  let ecsStatus: WidgetData["ecsStatus"] = "Unknown"
  let publicIp: string | undefined
  try {
    const ecsData = await aliyunRequest<{
      Instances?: {
        Instance?: ECSInstanceRecord[]
      }
    }>(`ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
      InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
      RegionId: config.regionId.trim()
    })

    const instance = ecsData.Instances?.Instance?.[0]
    ecsStatus = (instance?.Status as WidgetData["ecsStatus"]) || "Unknown"
    publicIp = getInstancePublicIp(instance)
  } catch {}

  // 3. 纯统计模式：小组件不执行任何关机请求，仅只读监控流量与状态

  // 4. 重置日推算
  const now = new Date()
  const currentDay = now.getDate()
  const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()
  const daysRemaining = Math.max(1, lastDay - currentDay + 1)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(2)
  const dailyUsage = buildDailyUsage(config, totalGB, now)
  const knownDailyValues = dailyUsage
    .map(item => item.valueGB)
    .filter((value): value is number => value !== null)
  const sevenDayTotalGB = knownDailyValues.length > 0
    ? Number(knownDailyValues.reduce((sum, value) => sum + value, 0).toFixed(2))
    : null
  const todayEstimatedGB = dailyUsage[dailyUsage.length - 1]?.valueGB ?? null

  const color = totalGB >= vpsCutoffReferenceGB
    ? "systemRed"
    : totalGB >= vpsCutoffReferenceGB - 15
      ? "systemOrange"
      : "systemGreen"

  return {
    totalGB,
    thresholdGB,
    vpsCutoffReferenceGB,
    cutoffRemainingGB,
    remainingGB,
    percentage,
    daysRemaining,
    dailyBudgetGB,
    dailyUsage,
    sevenDayTotalGB,
    todayEstimatedGB,
    updatedAt: now,
    ecsStatus,
    publicIp,
    color
  }
}

// ==================== 4. 小组件渲染视图 ====================

type ECSStatusMeta = {
  label: string
  shortLabel: string
  color: string
}

function getECSStatusMeta(status: WidgetData["ecsStatus"]): ECSStatusMeta {
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
  data: WidgetData
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
          shapeStyle: WIDGET_TRACK,
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
          <Text font={captionFont || 9} lineLimit={1} foregroundStyle="secondaryLabel">
            {caption}
          </Text>
        )}
        {subcaption && (
          <Text font={Math.max(7, (captionFont || 9) - 1)} lineLimit={1} foregroundStyle="secondaryLabel">
            {subcaption}
          </Text>
        )}
      </VStack>
    </ZStack>
  )
}

function formatEstimate(value: number | null, precision: number = 2): string {
  return value === null ? "--" : value.toFixed(precision)
}

function formatUpdateTime(date: Date): string {
  return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`
}

function WidgetHeader({
  data,
  compact = false
}: {
  data: WidgetData
  compact?: boolean
}) {
  const status = getECSStatusMeta(data.ecsStatus)
  return (
    <HStack alignment="center" frame={{ maxWidth: Infinity }}>
      <HStack spacing={5} alignment="center">
        <Image systemName="cloud.fill" font={compact ? 12 : 14} foregroundStyle="systemBlue" />
        <Text font={compact ? "caption2" : "subheadline"} bold lineLimit={1} foregroundStyle="label">
          阿里云 CDT
        </Text>
      </HStack>
      <Spacer />
      <HStack
        spacing={4}
        padding={{ horizontal: compact ? 5 : 7, vertical: compact ? 2 : 3 }}
        background={WIDGET_PANEL}
        clipShape={{ type: "capsule" }}
        alignment="center"
      >
        <Circle widgetAccentable fill={status.color} frame={{ width: compact ? 5 : 6, height: compact ? 5 : 6 }} />
        <Text font={compact ? 8 : 9} bold lineLimit={1} foregroundStyle={status.color}>
          {compact ? status.shortLabel : status.label}
        </Text>
      </HStack>
    </HStack>
  )
}

function WidgetProgressBar({ data }: { data: WidgetData }) {
  return (
    <VStack spacing={4} frame={{ maxWidth: Infinity }}>
      <ProgressView
        progressViewStyle="linear"
        value={Math.max(0.01, Math.min(1, data.percentage / 100))}
        total={1}
        tint={data.color}
        frame={{ maxWidth: Infinity, height: 5 }}
      />
      <HStack frame={{ maxWidth: Infinity }} alignment="center">
        <Text font={8} foregroundStyle={WIDGET_SECONDARY}>本地参考值 {data.thresholdGB} GB</Text>
        <Spacer />
        <Text font={8} bold monospacedDigit foregroundStyle={data.color}>{data.percentage.toFixed(1)}%</Text>
      </HStack>
    </VStack>
  )
}

function WidgetMetric({
  label,
  value,
  accent = "label",
  alignment = "leading"
}: {
  label: string
  value: string
  accent?: string | any
  alignment?: "leading" | "center" | "trailing"
}) {
  return (
    <VStack alignment={alignment} spacing={2} frame={{ maxWidth: Infinity }}>
      <Text font={8} lineLimit={1} foregroundStyle={WIDGET_TERTIARY}>{label}</Text>
      <Text font={13} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle={accent}>
        {value}
      </Text>
    </VStack>
  )
}

function DailyBars({
  data,
  chartHeight,
  barWidth,
  spacing,
  showValues,
  fullWeekday
}: {
  data: WidgetData
  chartHeight: number
  barWidth: number
  spacing: number
  showValues: boolean
  fullWeekday: boolean
}) {
  const knownValues = data.dailyUsage
    .map(item => item.valueGB)
    .filter((value): value is number => value !== null)
  const maximum = Math.max(0.01, ...knownValues)

  return (
    <HStack spacing={spacing} alignment="bottom" frame={{ maxWidth: Infinity }}>
      {data.dailyUsage.map(point => {
        const fillHeight = point.valueGB === null || point.valueGB <= 0
          ? 0
          : Math.max(7, Math.round((point.valueGB / maximum) * chartHeight))
        const label = point.isToday ? "今天" : fullWeekday ? `周${point.label}` : point.label
        const fillColor = point.isToday ? "systemBlue" : "systemGreen"

        return (
          <VStack key={point.date} spacing={3} alignment="center" frame={{ maxWidth: Infinity }}>
            {showValues && (
              <Text
                font={8}
                bold={point.isToday}
                monospacedDigit
                lineLimit={1}
                minScaleFactor={0.72}
                foregroundStyle={point.isToday ? "systemBlue" : "secondaryLabel"}
              >
                {formatEstimate(point.valueGB, fullWeekday ? 2 : 1)}
              </Text>
            )}
            <VStack
              spacing={0}
              frame={{ width: barWidth, height: chartHeight, alignment: "bottom" }}
              background={WIDGET_TRACK}
              clipShape={{ type: "capsule" }}
            >
              <Spacer />
              {point.valueGB !== null && point.valueGB > 0 && (
                <VStack
                  frame={{ width: barWidth, height: fillHeight }}
                  background={fillColor}
                  clipShape={{ type: "capsule" }}
                />
              )}
            </VStack>
            <Text
              font={8}
              bold={point.isToday}
              lineLimit={1}
              foregroundStyle={point.isToday ? "systemBlue" : "secondaryLabel"}
            >
              {label}
            </Text>
          </VStack>
        )
      })}
    </HStack>
  )
}

/** 未配置提示视图 */
function NotConfiguredWidgetView() {
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
        请在 Scripting 中点开此脚本，填入阿里云 AK/SK 与 ECS 实例信息。
      </Text>
      <Spacer />
      <Text font="caption2" bold foregroundStyle="systemBlue">
        轻点进入配置 &gt;
      </Text>
    </VStack>
  )
}

/** 小号小组件 (systemSmall) */
function SmallWidgetView({ data }: { data: WidgetData }) {
  return (
    <VStack
      alignment="leading"
      spacing={8}
      padding={{ horizontal: 13, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <WidgetHeader data={data} compact />
      <VStack
        alignment="leading"
        spacing={5}
        padding={{ horizontal: 10, vertical: 9 }}
        background={WIDGET_PANEL}
        clipShape={{ type: "rect", cornerRadius: 14, style: "continuous" }}
        frame={{ maxWidth: Infinity }}
      >
        <Text font={8} foregroundStyle={WIDGET_SECONDARY}>本月互联网出网</Text>
        <HStack alignment="lastTextBaseline">
          <Text font={27} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle="label">
            {data.totalGB.toFixed(2)}
          </Text>
          <Text font={10} foregroundStyle={WIDGET_SECONDARY} padding={{ leading: 3 }}>GB</Text>
          <Spacer />
          <Text font={9} bold monospacedDigit foregroundStyle={data.color}>
            {data.percentage.toFixed(1)}%
          </Text>
        </HStack>
        <WidgetProgressBar data={data} />
      </VStack>

      <HStack spacing={7} alignment="top" frame={{ maxWidth: Infinity }}>
        <WidgetMetric label="参考余量" value={`${data.remainingGB.toFixed(1)} GB`} accent={data.color} />
        <Divider frame={{ height: 27 }} />
        <WidgetMetric label="距结算" value={`${data.daysRemaining} 天`} alignment="center" />
      </HStack>

      <HStack alignment="center" frame={{ maxWidth: Infinity }}>
        <Text font={8} lineLimit={1} foregroundStyle={WIDGET_TERTIARY}>
          {formatUpdateTime(data.updatedAt)} 更新
        </Text>
        <Spacer />
        <Text font={8} lineLimit={1} foregroundStyle={WIDGET_TERTIARY}>
          ECS {getECSStatusMeta(data.ecsStatus).shortLabel}
        </Text>
      </HStack>
    </VStack>
  )
}

/** 中号小组件 (systemMedium) */
function MediumWidgetView({ data }: { data: WidgetData }) {
  return (
    <VStack
      alignment="leading"
      spacing={8}
      padding={{ horizontal: 15, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <WidgetHeader data={data} />
      <HStack spacing={12} alignment="center" frame={{ maxWidth: Infinity, maxHeight: Infinity }}>
        <VStack
          alignment="leading"
          spacing={5}
          padding={{ horizontal: 11, vertical: 9 }}
          background={WIDGET_PANEL}
          clipShape={{ type: "rect", cornerRadius: 14, style: "continuous" }}
          frame={{ width: 120 }}
        >
          <Text font={8} foregroundStyle={WIDGET_SECONDARY}>本月互联网出网</Text>
          <HStack alignment="lastTextBaseline" spacing={3}>
            <Text font={25} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle="label">
              {data.totalGB.toFixed(2)}
            </Text>
            <Text font={9} foregroundStyle={WIDGET_SECONDARY}>GB</Text>
          </HStack>
          <WidgetProgressBar data={data} />
        </VStack>

        <VStack alignment="leading" spacing={8} frame={{ maxWidth: Infinity }}>
          <HStack spacing={12} frame={{ maxWidth: Infinity }}>
            <WidgetMetric label="参考余量" value={`${data.remainingGB.toFixed(1)} GB`} accent={data.color} />
            <WidgetMetric label="日均可用" value={`${data.dailyBudgetGB} GB`} />
          </HStack>
          <HStack spacing={12} frame={{ maxWidth: Infinity }}>
            <WidgetMetric label="距结算" value={`${data.daysRemaining} 天`} />
            <WidgetMetric label="近 7 日" value={`${formatEstimate(data.sevenDayTotalGB)} GB`} />
          </HStack>
        </VStack>
      </HStack>
      <DailyBars data={data} chartHeight={28} barWidth={11} spacing={2} showValues={false} fullWeekday={false} />
    </VStack>
  )
}

/** 大号小组件 (systemLarge) */
function LargeWidgetView({ data }: { data: WidgetData }) {
  return (
    <VStack
      alignment="leading"
      spacing={10}
      padding={{ horizontal: 17, vertical: 15 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <WidgetHeader data={data} />

      <HStack spacing={16} alignment="center" frame={{ maxWidth: Infinity }}>
        <TrafficRing
          data={data}
          size={106}
          lineWidth={9}
          value={data.totalGB.toFixed(2)}
          caption="GB 本月已用"
          subcaption={`${data.percentage.toFixed(1)}%`}
          valueFont={22}
          captionFont={9}
        />
        <VStack
          alignment="leading"
          spacing={9}
          padding={{ horizontal: 13, vertical: 11 }}
          background={WIDGET_PANEL}
          clipShape={{ type: "rect", cornerRadius: 14, style: "continuous" }}
          frame={{ maxWidth: Infinity }}
        >
          <HStack spacing={12} frame={{ maxWidth: Infinity }}>
            <WidgetMetric label="参考余量" value={`${data.remainingGB.toFixed(2)} GB`} accent={data.color} />
            <WidgetMetric label="距结算" value={`${data.daysRemaining} 天`} alignment="trailing" />
          </HStack>
          <HStack spacing={12} frame={{ maxWidth: Infinity }}>
            <WidgetMetric label="今日估算" value={`${formatEstimate(data.todayEstimatedGB)} GB`} />
            <WidgetMetric label="近 7 日" value={`${formatEstimate(data.sevenDayTotalGB)} GB`} alignment="trailing" />
          </HStack>
          <WidgetProgressBar data={data} />
        </VStack>
      </HStack>

      <Divider />

      <HStack alignment="center" frame={{ maxWidth: Infinity }}>
        <Text font={10} lineLimit={1} foregroundStyle="secondaryLabel">每日估算用量</Text>
        <Spacer />
        <Text font={9} bold lineLimit={1} foregroundStyle="secondaryLabel">单位 GB</Text>
      </HStack>

      <DailyBars
        data={data}
        chartHeight={82}
        barWidth={26}
        spacing={8}
        showValues={true}
        fullWeekday={true}
      />

      <HStack alignment="center" frame={{ maxWidth: Infinity }}>
        <HStack spacing={5} alignment="center">
          <Image systemName="clock" font={9} foregroundStyle="systemOrange" />
          <Text font={9} bold lineLimit={1} foregroundStyle="systemOrange">日用量为本机采样估算</Text>
        </HStack>
        <Spacer />
        <Text font={9} monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
          {formatUpdateTime(data.updatedAt)} 更新
        </Text>
      </HStack>
    </VStack>
  )
}

/** 锁屏圆形小组件 (accessoryCircular) */
function AccessoryCircularView({ data }: { data: WidgetData }) {
  return (
    <ZStack
      alignment="center"
      widgetBackground="clear"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <TrafficRing
        data={data}
        size={52}
        lineWidth={5}
        value={`${data.percentage.toFixed(0)}%`}
        caption="CDT"
        valueFont={12}
        captionFont={7}
      />
    </ZStack>
  )
}

/** 锁屏矩形小组件 (accessoryRectangular) */
function AccessoryRectangularView({ data }: { data: WidgetData }) {
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
            <Text font={9} bold lineLimit={1} foregroundStyle={status.color}>
              {status.shortLabel}
            </Text>
          </HStack>
        </HStack>
        <Text font={9} lineLimit={1} foregroundStyle="secondaryLabel">
          参考余量 {data.remainingGB.toFixed(1)} GB · VPS 线 {data.vpsCutoffReferenceGB} GB
        </Text>
      </VStack>
    </HStack>
  )
}

/** 锁屏行内小组件 (accessoryInline) */
function AccessoryInlineView({ data }: { data: WidgetData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <Text lineLimit={1} monospacedDigit>
      CDT {data.totalGB.toFixed(2)}/{data.thresholdGB}G · {data.vpsCutoffReferenceGB}线余{data.cutoffRemainingGB.toFixed(1)}G · {status.shortLabel}
    </Text>
  )
}

function presentWidget(view: any): void {
  // `policy: "after"` is an earliest requested refresh time; iOS may defer it.
  Widget.present(view, {
    policy: "after",
    date: new Date(Date.now() + WIDGET_REFRESH_AFTER_MS)
  })
}

function presentDataWidget(data: WidgetData): void {
  const family = Widget.family

  if (family === "accessoryInline") {
    presentWidget(<AccessoryInlineView data={data} />)
  } else if (family === "accessoryCircular") {
    presentWidget(<AccessoryCircularView data={data} />)
  } else if (family === "accessoryRectangular") {
    presentWidget(<AccessoryRectangularView data={data} />)
  } else if (family === "systemLarge") {
    presentWidget(<LargeWidgetView data={data} />)
  } else if (family === "systemMedium") {
    presentWidget(<MediumWidgetView data={data} />)
  } else {
    presentWidget(<SmallWidgetView data={data} />)
  }
}

// ==================== 5. 主执行入口 ====================

async function main() {
  try {
    const config = loadSavedConfig()

    // 若未配置，渲染引导提示
    if (!isConfigReady(config)) {
      presentWidget(<NotConfiguredWidgetView />)
      return
    }

    const data = await fetchWidgetData(config)
    presentDataWidget(data)
  } catch (err: any) {
    console.error("小组件加载失败:", err)
    // 弱网容灾：控制台快照缺少日采样字段，必须校验并适配后才能渲染。
    try {
      if (typeof Storage !== "undefined" && Storage?.get) {
        const raw = Storage.get(DASHBOARD_SNAPSHOT_STORAGE_KEY)
        if (raw) {
          const parsed = typeof raw === "string" ? JSON.parse(raw) : raw
          const cached = adaptDashboardSnapshotForWidget(parsed)
          if (!cached) throw new Error("本地快照数据不完整")
          presentDataWidget(cached)
          return
        }
      }
    } catch {}

    presentWidget(
      <VStack
        alignment="leading"
        spacing={6}
        padding={{ horizontal: 14, vertical: 12 }}
        widgetBackground="systemBackground"
        frame={{ maxWidth: Infinity, maxHeight: Infinity }}
      >
        <HStack spacing={6} alignment="center">
          <Image systemName="exclamationmark.triangle.fill" font={13} foregroundStyle="systemRed" />
          <Text font="caption1" bold foregroundStyle="systemRed">
            获取失败
          </Text>
        </HStack>
        <Text font="caption2" foregroundStyle="secondaryLabel" lineLimit={3}>
          {err?.message || "网络请求超时或凭据无效"}
        </Text>
      </VStack>
    )
  }
}

main()
