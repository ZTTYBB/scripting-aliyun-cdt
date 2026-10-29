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
  Circle
} from "scripting"
import { MediumWidgetView, SmallWidgetView, LargeWidgetView, MultiAccountWidgetView, AccountWidgetItem } from "./medium_widget"
import {
  DailyUsagePoint,
  createSnapshot,
  readSnapshot,
  recordTrafficSample,
  readDailyUsage,
  sumCompleteSevenDays,
  assertSampleBillingMonth,
  withRequestTimeout,
  aliyunHttpError,
  chinaMonthProgress,
  normalizeEcsStatus,
  usagePercentage,
  widgetErrorHint,
  accountDisplayName,
  loadAccountProfiles,
  scopedStorageKey,
  selectWidgetAccounts
} from "./monitor_runtime"

const WIDGET_TRACK = {
  light: "rgba(142, 142, 147, 0.18)",
  dark: "rgba(142, 142, 147, 0.36)"
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
  id?: string
  name?: string
  site?: string
}

const STORAGE_KEY = "aliyun_cdt_monitor_config"
const DASHBOARD_SNAPSHOT_STORAGE_KEY = "aliyun_cdt_dashboard_cache"
const WIDGET_SNAPSHOT_STORAGE_KEY = "aliyun_cdt_widget_cache"
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
  isCached?: boolean
  accountName?: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value)
}

function parseCachedDate(value: unknown): Date | null {
  if (value instanceof Date || Object.prototype.toString.call(value) === "[object Date]") {
    const date = value as Date
    return Number.isFinite(date.getTime()) ? date : null
  }
  if (typeof value !== "string" && typeof value !== "number") return null
  const date = new Date(value)
  return Number.isFinite(date.getTime()) ? date : null
}

/**
 * The app dashboard snapshot has no embedded chart series. Validate its stable
 * source fields, then restore the shared local sampling history for fallback.
 */
function adaptDashboardSnapshotForWidget(raw: unknown, config: AppConfig, now: Date = new Date()): WidgetData | null {
  if (!isRecord(raw)) return null

  const totalGB = raw.totalGB
  const thresholdGB = config.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB
  const updatedAt = parseCachedDate(raw.updatedAt)

  if (
    !isFiniteNumber(totalGB) || totalGB < 0 ||
    !isFiniteNumber(thresholdGB) || thresholdGB <= 0 ||
    !isFiniteNumber(vpsCutoffReferenceGB) || vpsCutoffReferenceGB <= 0 ||
    !updatedAt
  ) {
    return null
  }

  const { daysRemaining } = chinaMonthProgress(now)
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = usagePercentage(totalGB, thresholdGB)
  const color = totalGB >= vpsCutoffReferenceGB
    ? "systemRed"
    : totalGB >= vpsCutoffReferenceGB - 15
      ? "systemOrange"
      : "systemGreen"
  const publicIp = typeof raw.publicIp === "string" && raw.publicIp.trim()
    ? raw.publicIp.trim()
    : undefined
  const dailyUsage = readDailyUsage(config, now)
  const sevenDayTotalGB = sumCompleteSevenDays(dailyUsage)

  return {
    totalGB,
    thresholdGB,
    vpsCutoffReferenceGB,
    cutoffRemainingGB,
    remainingGB,
    percentage,
    daysRemaining,
    dailyBudgetGB: (remainingGB / daysRemaining).toFixed(2),
    dailyUsage,
    sevenDayTotalGB,
    todayEstimatedGB: dailyUsage[dailyUsage.length - 1]?.valueGB ?? null,
    updatedAt,
    ecsStatus: normalizeEcsStatus(raw.ecsStatus),
    publicIp,
    color,
    isCached: true
  }
}

async function fetchWidgetData(config: AppConfig): Promise<WidgetData> {
  const sampledAt = new Date()
  // 1. 查询 CDT 流量
  const cdtRequest = aliyunRequest<{
    TrafficDetails?: Array<{ Traffic?: number }>
  }>("cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config)

  // 2. CDT/ECS 并行，避免叠加两个超时时间；ECS 失败仍可展示流量。
  const ecsRequest = aliyunRequest<{
    Instances?: { Instance?: ECSInstanceRecord[] }
  }>(`ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
    InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
    RegionId: config.regionId.trim()
  }).catch(() => null)
  const [cdtData, ecsData] = await Promise.all([cdtRequest, ecsRequest])
  const now = new Date()
  assertSampleBillingMonth(sampledAt, now)
  const details = cdtData.TrafficDetails || []
  const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB > 0 ? config.trafficThresholdGB : DEFAULT_CONFIG.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB > 0 ? config.vpsCutoffReferenceGB : DEFAULT_CONFIG.vpsCutoffReferenceGB
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = usagePercentage(totalGB, thresholdGB)
  const instance = ecsData?.Instances?.Instance?.[0]
  const ecsStatus = normalizeEcsStatus(instance?.Status)
  const publicIp = getInstancePublicIp(instance)

  // 3. 纯统计模式：小组件不执行任何关机请求，仅只读监控流量与状态

  // 4. 重置日推算
  const { daysRemaining } = chinaMonthProgress(now)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(2)
  const dailyUsage = recordTrafficSample(config, totalGB, sampledAt)
  const sevenDayTotalGB = sumCompleteSevenDays(dailyUsage)
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
    updatedAt: sampledAt,
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
        caption={data.isCached ? "缓存" : "CDT"}
        valueFont={12}
        captionFont={9}
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
            <Text font={9} lineLimit={1} foregroundStyle="secondaryLabel">
              {data.isCached ? "缓存 · " : ""}{status.shortLabel}
            </Text>
          </HStack>
        </HStack>
        <Text font={9} lineLimit={1} foregroundStyle="secondaryLabel">
          {data.accountName ? `${data.accountName} · ` : ""}参考余量 {data.remainingGB.toFixed(1)} GB · VPS 线 {data.vpsCutoffReferenceGB} GB
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
      {data.accountName ? `${data.accountName} · ` : ""}{data.isCached ? "CDT 缓存" : "CDT"} {data.totalGB.toFixed(2)}/{data.thresholdGB}G · {data.vpsCutoffReferenceGB}线余{data.cutoffRemainingGB.toFixed(1)}G · {status.shortLabel}
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

/** 多账号汇总：锁屏行内组件，一行显示所有账号用量 */
function AccessoryMultiInlineView({ items }: { items: AccountWidgetItem[] }) {
  return (
    <Text lineLimit={1} monospacedDigit>
      {items.map(item => item.data
        ? `${item.name} ${item.data.totalGB.toFixed(1)}/${item.data.thresholdGB}G`
        : `${item.name} 失败`).join(" · ")}
    </Text>
  )
}

/** 多账号汇总：锁屏矩形组件，每个账号一行 */
function AccessoryMultiRectangularView({ items }: { items: AccountWidgetItem[] }) {
  return (
    <VStack
      alignment="leading"
      spacing={3}
      widgetBackground="clear"
      frame={{ maxWidth: Infinity, maxHeight: Infinity, alignment: "leading" }}
    >
      {items.slice(0, 3).map((item, index) => {
        const data = item.data as WidgetData | null
        const status = data ? getECSStatusMeta(data.ecsStatus) : null
        return (
          <HStack key={`${index}-${item.name}`} spacing={4} alignment="center">
            <Circle widgetAccentable fill={status ? status.color : "systemRed"} frame={{ width: 5, height: 5 }} />
            <Text font={12} fontWeight="semibold" lineLimit={1}>{item.name}</Text>
            <Spacer />
            <Text font={12} monospacedDigit lineLimit={1} foregroundStyle={data ? "label" : "secondaryLabel"}>
              {data ? `${data.totalGB.toFixed(1)}/${data.thresholdGB}G${data.isCached ? "*" : ""}` : "获取失败"}
            </Text>
          </HStack>
        )
      })}
    </VStack>
  )
}

function WidgetMessageView({ title, message, color = "systemRed", icon = "exclamationmark.triangle.fill" }: {
  title: string
  message: string
  color?: string
  icon?: string
}) {
  if (Widget.family === "accessoryInline") {
    return <Text lineLimit={1}>CDT {title}</Text>
  }
  return (
    <VStack
      alignment="leading"
      spacing={6}
      padding={{ horizontal: 14, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <HStack spacing={6} alignment="center">
        <Image systemName={icon} font={13} foregroundStyle={color} />
        <Text font="caption1" bold foregroundStyle={color} lineLimit={1}>
          {title}
        </Text>
      </HStack>
      <Text font="caption2" foregroundStyle="secondaryLabel" lineLimit={4}>
        {message}
      </Text>
    </VStack>
  )
}

// ==================== 5. 主执行入口 ====================

function readActiveAccountId(): string | undefined {
  try {
    const raw = typeof Storage !== "undefined" ? Storage?.get?.(STORAGE_KEY) : undefined
    const parsed = typeof raw === "string" ? JSON.parse(raw) : raw
    return typeof parsed?.id === "string" ? parsed.id : undefined
  } catch {
    return undefined
  }
}

/** 弱网容灾：先读本账号的小组件快照，再读控制台快照；旧版未分账号的键作为兜底。 */
function loadCachedWidgetData(config: AppConfig): WidgetData | null {
  try {
    if (typeof Storage === "undefined" || !Storage?.get) return null
    const keys = [
      scopedStorageKey(WIDGET_SNAPSHOT_STORAGE_KEY, config),
      WIDGET_SNAPSHOT_STORAGE_KEY,
      scopedStorageKey(DASHBOARD_SNAPSHOT_STORAGE_KEY, config),
      DASHBOARD_SNAPSHOT_STORAGE_KEY
    ]
    for (const key of keys) {
      const cached = adaptDashboardSnapshotForWidget(readSnapshot(Storage.get(key), config), config)
      if (cached) return cached
    }
  } catch {}
  return null
}

async function loadAccountWidgetData(config: AppConfig): Promise<WidgetData> {
  const data = await fetchWidgetData(config)
  assertSampleBillingMonth(data.updatedAt)
  try {
    if (typeof Storage !== "undefined" && Storage?.get && Storage?.set) {
      const key = scopedStorageKey(WIDGET_SNAPSHOT_STORAGE_KEY, config)
      const existing = readSnapshot<WidgetData>(Storage.get(key), config)
      if (!existing || existing.updatedAt.getTime() <= data.updatedAt.getTime()) {
        Storage.set(key, JSON.stringify(createSnapshot(config, data)))
      }
    }
  } catch (error) {
    console.error("保存小组件快照失败:", error)
  }
  return data
}

async function presentAllAccounts(accounts: AppConfig[], all: AppConfig[]): Promise<void> {
  const items: AccountWidgetItem[] = await Promise.all(accounts.map(async config => {
    const name = accountDisplayName(config, all.indexOf(config))
    try {
      return { name, site: config.site, data: await loadAccountWidgetData(config) }
    } catch (err: any) {
      console.error(`小组件账号 ${name} 加载失败:`, err)
      const cached = loadCachedWidgetData(config)
      return { name, site: config.site, data: cached, error: cached ? undefined : widgetErrorHint(err?.message) }
    }
  }))
  const family = Widget.family
  if (family === "accessoryInline") {
    presentWidget(<AccessoryMultiInlineView items={items} />)
  } else if (family === "accessoryRectangular") {
    presentWidget(<AccessoryMultiRectangularView items={items} />)
  } else if (family === "accessoryCircular") {
    const first = items.find(item => item.data)
    if (first?.data) presentDataWidget(first.data as WidgetData)
    else presentWidget(<WidgetMessageView title="获取失败" message={items[0]?.error || "请稍后重试"} />)
  } else {
    presentWidget(<MultiAccountWidgetView items={items} family={family} />)
  }
}

async function main() {
  const accounts = loadAccountProfiles<AppConfig>(DEFAULT_CONFIG)
  if (accounts.length === 0) {
    presentWidget(<NotConfiguredWidgetView />)
    return
  }

  // 长按小组件 → 编辑小组件 → Parameter：留空/国内/国外/账号名/序号/全部
  const parameter = typeof Widget !== "undefined" ? (Widget as any)?.parameter : undefined
  const selection = selectWidgetAccounts(accounts, parameter, readActiveAccountId())
  if (selection.accounts.length === 0) {
    const names = accounts.map((item, index) => accountDisplayName(item, index)).join("、")
    presentWidget(
      <WidgetMessageView
        title={`未找到账号「${selection.unmatched}」`}
        message={`编辑小组件的 Parameter 可填：${names}、全部；留空显示 App 当前账号。`}
        color="systemOrange"
        icon="person.crop.circle.badge.questionmark"
      />
    )
    return
  }
  if (selection.mode === "all") {
    await presentAllAccounts(selection.accounts, accounts)
    return
  }

  const config = selection.accounts[0]
  const accountName = accounts.length > 1 ? accountDisplayName(config, accounts.indexOf(config)) : undefined
  try {
    const data = await loadAccountWidgetData(config)
    data.accountName = accountName
    presentDataWidget(data)
  } catch (err: any) {
    console.error("小组件加载失败:", err)
    const cached = loadCachedWidgetData(config)
    if (cached) {
      cached.accountName = accountName
      presentDataWidget(cached)
      return
    }
    presentWidget(
      <WidgetMessageView
        title={accountName ? `${accountName} 获取失败` : "获取失败"}
        message={widgetErrorHint(err?.message)}
      />
    )
  }
}

main()
