/**
 * ============================================================================
 * 阿里云 CDT 流量监控 & ECS 智控【单文件通用版 (All-In-One)】
 * ============================================================================
 * 特性：
 * 1. 零硬编码凭据：所有人下载即可直接使用，首次打开自动弹出设置界面。
 * 2. 凭据仅存储在用户 iPhone 本机 Scripting Storage 中，安全可靠。
 * 3. 桌面小组件模式：自动根据尺寸呈现小号 / 中号 / 大号 / 锁屏组件。
 * 4. App 内控制台模式：呈现交互式仪表盘，支持实时刷新与一键开机 / 关机、设置修改。
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
  Button,
  Spacer,
  Divider,
  TextField,
  Toggle,
  Toolbar,
  ToolbarItem,
  NavigationStack,
  useState,
  useEffect,
  useCallback
} from "scripting"

// ==================== 1. 本地存储配置管理 ====================

interface AppConfig {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  resetDayOfMonth: number
  autoStopOnExceed: boolean
}

const STORAGE_KEY = "aliyun_cdt_monitor_config"
const TRAFFIC_HISTORY_KEY = "aliyun_cdt_daily_history_v1"

const DEFAULT_CONFIG: AppConfig = {
  accessKeyId: "",
  accessKeySecret: "",
  regionId: "cn-hongkong",
  ecsInstanceId: "",
  trafficThresholdGB: 180,
  resetDayOfMonth: 1,
  autoStopOnExceed: true
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
    console.error("加载配置失败:", e)
  }
  return { ...DEFAULT_CONFIG }
}

function saveConfigToStorage(cfg: AppConfig): void {
  try {
    if (typeof Storage !== "undefined" && Storage?.set) {
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

interface MonitorData {
  totalGB: number
  thresholdGB: number
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

async function fetchMonitorData(config: AppConfig): Promise<MonitorData> {
  const cdtData = await aliyunRequest<{
    TrafficDetails?: Array<{ Traffic?: number }>
  }>("cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config)

  const details = cdtData.TrafficDetails || []
  const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))

  const ecsData = await aliyunRequest<{
    Instances?: {
      Instance?: Array<{
        Status: string
        PublicIpAddress?: { IpAddress?: string[] }
      }>
    }
  }>(`ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
    InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
    RegionId: config.regionId.trim()
  })

  const instance = ecsData.Instances?.Instance?.[0]
  let ecsStatus = (instance?.Status as any) || "Unknown"
  const publicIp = instance?.PublicIpAddress?.IpAddress?.[0]

  if (config.autoStopOnExceed && totalGB >= thresholdGB && ecsStatus === "Running") {
    await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, "StopInstance", "2014-05-26", config, {
      InstanceId: config.ecsInstanceId.trim(),
      ForceStop: false
    })
    ecsStatus = "Stopping"
  }

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

  const color = percentage >= 90 ? "#FF453A" : percentage >= 70 ? "#FF9F0A" : "#30D158"

  return {
    totalGB,
    thresholdGB,
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

async function toggleECS(action: "start" | "stop", config: AppConfig) {
  const apiAction = action === "start" ? "StartInstance" : "StopInstance"
  await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, apiAction, "2014-05-26", config, {
    InstanceId: config.ecsInstanceId.trim(),
    ForceStop: false
  })
}

// ==================== 4. 小组件渲染视图 ====================

type ECSStatusMeta = {
  label: string
  shortLabel: string
  color: string
}

interface TrafficSnapshot {
  date: string
  totalGB: number
  updatedAt: number
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

function getECSStatusMeta(status: MonitorData["ecsStatus"]): ECSStatusMeta {
  switch (status) {
    case "Running":
      return { label: "运行中", shortLabel: "运行", color: "#30D158" }
    case "Starting":
      return { label: "启动中", shortLabel: "启动中", color: "#FF9F0A" }
    case "Stopping":
      return { label: "停止中", shortLabel: "停止中", color: "#FF9F0A" }
    case "Stopped":
      return { label: "已停止", shortLabel: "停止", color: "#8E8E93" }
    default:
      return { label: "状态未知", shortLabel: "未知", color: "#8E8E93" }
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
          shapeStyle: "rgba(142, 142, 147, 0.16)",
          strokeStyle: { lineWidth, lineCap: "round" }
        }}
        frame={{ width: size, height: size }}
      />
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
          <Text font={captionFont || 9} lineLimit={1} foregroundColor="#8E8E93">
            {caption}
          </Text>
        )}
        {subcaption && (
          <Text font={Math.max(7, (captionFont || 9) - 1)} lineLimit={1} foregroundColor="#8E8E93">
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

function DailyBars({
  data,
  chartHeight,
  barWidth,
  spacing,
  showValues,
  fullWeekday
}: {
  data: MonitorData
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
        const fillColor = point.isToday ? "#0A84FF" : "#30D158"

        return (
          <VStack key={point.date} spacing={3} alignment="center" frame={{ maxWidth: Infinity }}>
            {showValues && (
              <Text
                font={8}
                bold={point.isToday}
                monospacedDigit
                lineLimit={1}
                minScaleFactor={0.72}
                foregroundColor={point.isToday ? "#0A84FF" : "#8E8E93"}
              >
                {formatEstimate(point.valueGB, fullWeekday ? 2 : 1)}
              </Text>
            )}
            <VStack
              spacing={0}
              frame={{ width: barWidth, height: chartHeight, alignment: "bottom" }}
              background="rgba(142, 142, 147, 0.14)"
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
              foregroundColor={point.isToday ? "#0A84FF" : "#8E8E93"}
            >
              {label}
            </Text>
          </VStack>
        )
      })}
    </HStack>
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
        <Text font="subheadline" bold foregroundColor="#FF9F0A">
          尚未配置
        </Text>
      </HStack>
      <Text font="caption2" foregroundColor="#8E8E93">
        请在 Scripting 中打开此脚本完成阿里云凭据配置。
      </Text>
      <Spacer />
      <Text font="caption2" bold foregroundColor="#0A84FF">
        轻点进入配置 &gt;
      </Text>
    </VStack>
  )
}

function SmallWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <VStack
      alignment="leading"
      spacing={4}
      padding={{ horizontal: 10, vertical: 9 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <HStack alignment="center">
        <HStack spacing={4} alignment="center">
          <Image systemName="cloud.fill" font={12} foregroundStyle="systemBlue" />
          <Text font="caption2" bold lineLimit={1} foregroundStyle="label">
            CDT
          </Text>
        </HStack>
        <Spacer />
        <HStack spacing={4} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 6, height: 6 }} />
          <Text font="caption2" bold lineLimit={1} foregroundColor={status.color}>
            {status.shortLabel}
          </Text>
        </HStack>
      </HStack>

      <HStack frame={{ maxWidth: Infinity }} alignment="center">
        <Spacer />
        <TrafficRing
          data={data}
          size={76}
          lineWidth={7}
          value={data.totalGB.toFixed(2)}
          caption={`/ ${data.thresholdGB} GB`}
          subcaption={`${data.percentage.toFixed(1)}%`}
          valueFont={17}
          captionFont={8}
        />
        <Spacer />
      </HStack>

      <HStack spacing={4} alignment="top" frame={{ maxWidth: Infinity }}>
        <VStack alignment="leading" spacing={1} frame={{ maxWidth: Infinity }}>
          <Text font={8} lineLimit={1} foregroundColor="#8E8E93">今日估算</Text>
          <Text font={9} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} allowsTightening={true} foregroundStyle="label">
            {formatEstimate(data.todayEstimatedGB)} GB
          </Text>
        </VStack>
        <VStack alignment="center" spacing={1} frame={{ maxWidth: Infinity }}>
          <Text font={8} lineLimit={1} foregroundColor="#8E8E93">日均可用</Text>
          <Text font={9} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} allowsTightening={true} foregroundStyle="label">
            {data.dailyBudgetGB} GB
          </Text>
        </VStack>
        <VStack alignment="trailing" spacing={1} frame={{ maxWidth: Infinity }}>
          <Text font={8} lineLimit={1} foregroundColor="#8E8E93">近 7 日</Text>
          <Text font={9} bold monospacedDigit lineLimit={1} minScaleFactor={0.65} allowsTightening={true} foregroundStyle="label">
            {formatEstimate(data.sevenDayTotalGB)} GB
          </Text>
        </VStack>
      </HStack>
    </VStack>
  )
}

function MediumWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <VStack
      alignment="leading"
      spacing={7}
      padding={{ horizontal: 16, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <HStack alignment="center">
        <HStack spacing={6} alignment="center">
          <Image systemName="cloud.fill" font={14} foregroundStyle="systemBlue" />
          <Text font="subheadline" bold lineLimit={1} foregroundStyle="label">
            阿里云 CDT
          </Text>
        </HStack>
        <Spacer />
        <HStack spacing={5} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 7, height: 7 }} />
          <Text font={10} bold lineLimit={1} foregroundColor={status.color}>
            ECS {status.label}
          </Text>
        </HStack>
      </HStack>

      <HStack spacing={12} alignment="center" frame={{ maxWidth: Infinity, maxHeight: Infinity }}>
        <TrafficRing
          data={data}
          size={84}
          lineWidth={8}
          value={data.totalGB.toFixed(2)}
          caption="GB 已用"
          subcaption={`${data.percentage.toFixed(1)}%`}
          valueFont={18}
          captionFont={8}
        />

        <VStack alignment="leading" spacing={5} frame={{ maxWidth: Infinity, alignment: "leading" }}>
          <HStack spacing={10} frame={{ maxWidth: Infinity }} alignment="top">
            <VStack alignment="leading" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">
                本月剩余
              </Text>
              <HStack alignment="bottom" spacing={2}>
                <Text font={15} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                  {data.remainingGB.toFixed(2)}
                </Text>
                <Text font={8} lineLimit={1} foregroundColor="#8E8E93" padding={{ bottom: 1 }}>GB</Text>
              </HStack>
            </VStack>
            <Spacer />
            <VStack alignment="trailing" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">
                日均可用
              </Text>
              <HStack alignment="bottom" spacing={2}>
                <Text font={15} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                  {data.dailyBudgetGB}
                </Text>
                <Text font={8} lineLimit={1} foregroundColor="#8E8E93" padding={{ bottom: 1 }}>GB/天</Text>
              </HStack>
            </VStack>
          </HStack>

          <HStack alignment="center" frame={{ maxWidth: Infinity }}>
            <Text font={8} lineLimit={1} foregroundColor="#8E8E93">
              7 日估算 · 余 {data.daysRemaining} 天
            </Text>
            <Spacer />
            <Text font={9} bold monospacedDigit lineLimit={1} foregroundStyle="label">
              {formatEstimate(data.sevenDayTotalGB)} GB
            </Text>
          </HStack>

          <DailyBars
            data={data}
            chartHeight={30}
            barWidth={12}
            spacing={2}
            showValues={true}
            fullWeekday={false}
          />
        </VStack>
      </HStack>
    </VStack>
  )
}

function LargeWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <VStack
      alignment="leading"
      spacing={9}
      padding={{ horizontal: 18, vertical: 15 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      <HStack alignment="center">
        <HStack spacing={6} alignment="center">
          <Image systemName="cloud.fill" font={14} foregroundStyle="systemBlue" />
          <Text font="subheadline" bold lineLimit={1} foregroundStyle="label">阿里云 CDT</Text>
        </HStack>
        <Spacer />
        <HStack spacing={5} alignment="center">
          <Circle widgetAccentable fill={status.color} frame={{ width: 7, height: 7 }} />
          <Text font={10} bold lineLimit={1} foregroundColor={status.color}>ECS {status.label}</Text>
        </HStack>
      </HStack>

      <HStack spacing={18} alignment="center" frame={{ maxWidth: Infinity }}>
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

        <VStack alignment="leading" spacing={9} frame={{ maxWidth: Infinity }}>
          <HStack alignment="top" frame={{ maxWidth: Infinity }}>
            <VStack alignment="leading" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">本月剩余</Text>
              <Text font={17} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                {data.remainingGB.toFixed(2)} GB
              </Text>
            </VStack>
            <Spacer />
            <VStack alignment="trailing" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">距结算</Text>
              <Text font={17} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                {data.daysRemaining} 天
              </Text>
            </VStack>
          </HStack>

          <HStack alignment="top" frame={{ maxWidth: Infinity }}>
            <VStack alignment="leading" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">今日估算</Text>
              <Text font={14} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                {formatEstimate(data.todayEstimatedGB)} GB
              </Text>
            </VStack>
            <Spacer />
            <VStack alignment="trailing" spacing={2}>
              <Text font={9} lineLimit={1} foregroundColor="#8E8E93">近 7 日</Text>
              <Text font={14} bold monospacedDigit lineLimit={1} foregroundStyle="label">
                {formatEstimate(data.sevenDayTotalGB)} GB
              </Text>
            </VStack>
          </HStack>

          <HStack alignment="bottom" frame={{ maxWidth: Infinity }}>
            <Text font={9} lineLimit={1} foregroundColor="#8E8E93">剩余日均可用</Text>
            <Spacer />
            <Text font={15} bold monospacedDigit lineLimit={1} foregroundStyle="label">
              {data.dailyBudgetGB} GB/天
            </Text>
          </HStack>
        </VStack>
      </HStack>

      <Divider />
      <HStack alignment="center" frame={{ maxWidth: Infinity }}>
        <Text font={10} lineLimit={1} foregroundColor="#8E8E93">每日估算用量</Text>
        <Spacer />
        <Text font={9} bold lineLimit={1} foregroundColor="#8E8E93">单位 GB</Text>
      </HStack>

      <DailyBars
        data={data}
        chartHeight={82}
        barWidth={26}
        spacing={8}
        showValues={true}
        fullWeekday={true}
      />

      <Spacer />
      <HStack alignment="center" frame={{ maxWidth: Infinity }}>
        <HStack spacing={5} alignment="center">
          <Image systemName="clock" font={9} foregroundStyle="#FF9F0A" />
          <Text font={9} bold lineLimit={1} foregroundColor="#C66B00">日用量为本机采样估算</Text>
        </HStack>
        <Spacer />
        <Text font={9} monospacedDigit lineLimit={1} foregroundColor="#8E8E93">
          {formatUpdateTime(data.updatedAt)} 更新
        </Text>
      </HStack>
    </VStack>
  )
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
            <Text font={9} bold lineLimit={1} foregroundColor={status.color}>
              {status.shortLabel}
            </Text>
          </HStack>
        </HStack>
        <Text font={9} lineLimit={1} foregroundColor="#8E8E93">
          剩余 {data.remainingGB.toFixed(1)} GB · {data.daysRemaining} 天重置
        </Text>
      </VStack>
    </HStack>
  )
}

function AccessoryInlineWidget({ data }: { data: MonitorData }) {
  const status = getECSStatusMeta(data.ecsStatus)

  return (
    <Text lineLimit={1} monospacedDigit>
      CDT {data.totalGB.toFixed(2)}/{data.thresholdGB}G · {status.shortLabel}
    </Text>
  )
}

// ==================== 5. Apple iOS 26 Liquid Glass 材质与动效系统 ====================

declare const UIGlass: {
  clear: () => {
    interactive: (val: boolean) => any
  }
} | undefined

/**
 * 液态玻璃控件专用 GlassEffect 注入
 * 严格遵循 HIG 分层法则：仅功能操作控件（按钮、胶囊、开关）应用液态玻璃材质，内容卡片保持纯白不透明
 */
function liquidGlass(interactive: boolean = true) {
  try {
    if (typeof UIGlass !== "undefined" && typeof UIGlass.clear === "function") {
      return {
        glassEffect: {
          glass: interactive ? UIGlass.clear().interactive(true) : UIGlass.clear().interactive(false),
          shape: "capsule" as const
        },
        glassEffectTransition: "materialize" as const
      }
    }
  } catch {
    // fallback
  }
  return {}
}

// ==================== 6. 设置配置面板视图 (Apple Liquid Glass Controls) ====================

function SettingsComponent({
  currentConfig,
  onSave,
  onCancel
}: {
  currentConfig: AppConfig
  onSave: (newConfig: AppConfig) => void
  onCancel: () => void
}) {
  const [ak, setAk] = useState(currentConfig.accessKeyId || "")
  const [sk, setSk] = useState(currentConfig.accessKeySecret || "")
  const [region, setRegion] = useState(currentConfig.regionId || "cn-hongkong")
  const [ecsId, setEcsId] = useState(currentConfig.ecsInstanceId || "")
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || 180))
  const [autoStop, setAutoStop] = useState(currentConfig.autoStopOnExceed ?? true)
  const [errorNotice, setErrorNotice] = useState<string | null>(null)
  const [successNotice, setSuccessNotice] = useState<string | null>(null)

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
        setSuccessNotice(`🎉 成功智能识别并填入 ${count} 项配置！`)
        if (typeof Dialog !== "undefined" && Dialog.alert) {
          await Dialog.alert({
            title: "识别成功",
            message: `已自动解析并填入 ${count} 项阿里云信息，确认无误后点击下方保存即可！`
          })
        }
      } else {
        setErrorNotice("未能从剪贴板识别出阿里云凭据格式，请点击各输入项右侧按钮录入。")
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
    onConfirm: (val: string) => void
  ) => {
    if (typeof Dialog !== "undefined" && Dialog.prompt) {
      const res = await Dialog.prompt({
        title,
        message,
        defaultValue: currentVal,
        placeholder,
        confirmLabel: "确定",
        cancelLabel: "取消"
      })
      if (res !== null) {
        onConfirm(res.trim())
      }
    }
  }

  const handleSave = () => {
    if (!ak.trim() || !sk.trim() || !ecsId.trim()) {
      setErrorNotice("请填写完整的 AccessKey ID、Secret 与 ECS 实例 ID！")
      return
    }
    const numThreshold = parseFloat(threshold) || 180
    const newCfg: AppConfig = {
      accessKeyId: ak.trim(),
      accessKeySecret: sk.trim(),
      regionId: region.trim() || "cn-hongkong",
      ecsInstanceId: ecsId.trim(),
      trafficThresholdGB: numThreshold,
      resetDayOfMonth: 1,
      autoStopOnExceed: autoStop
    }
    saveConfigToStorage(newCfg)
    onSave(newCfg)
  }

  return (
    <ScrollView background="#F2F2F7" showsIndicators={false}>
      <VStack
        alignment="leading"
        spacing={16}
        padding={{ horizontal: 16, top: 12, bottom: 40 }}
      >
        {/* 顶部导航标题栏 */}
        <HStack alignment="center" padding={{ horizontal: 4, bottom: 4 }}>
          {isConfigReady(currentConfig) ? (
            <Button action={onCancel} buttonStyle="plain">
              <HStack
                spacing={5}
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(142, 142, 147, 0.12)"
                border={{ style: "rgba(142, 142, 147, 0.20)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                alignment="center"
                {...liquidGlass(true)}
              >
                <Image systemName="chevron.backward" font={13} fontWeight="bold" foregroundStyle="#007AFF" />
                <Text font="caption1" bold foregroundColor="#007AFF">返回</Text>
              </HStack>
            </Button>
          ) : (
            <Spacer frame={{ width: 60 }} />
          )}
          <Spacer />
          <Text font="headline" bold foregroundColor="#1C1C1E">
            参数配置
          </Text>
          <Spacer />
          <Button action={handleSave} buttonStyle="plain">
            <HStack
              spacing={4}
              padding={{ horizontal: 14, vertical: 6 }}
              background="rgba(0, 122, 255, 0.12)"
              border={{ style: "rgba(0, 122, 255, 0.28)", width: 0.75 }}
              clipShape={{ type: "capsule" }}
              alignment="center"
              {...liquidGlass(true)}
            >
              <Text font="caption1" bold foregroundColor="#007AFF">保存</Text>
            </HStack>
          </Button>
        </HStack>

        {/* 提示横幅 */}
        {errorNotice && (
          <HStack
            padding={{ horizontal: 16, vertical: 12 }}
            background="rgba(255, 59, 48, 0.10)"
            border={{ style: "rgba(255, 59, 48, 0.25)", width: 0.75 }}
            clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
          >
            <Text font="caption1" bold foregroundColor="#FF3B30">
              ⚠️ {errorNotice}
            </Text>
          </HStack>
        )}
        {successNotice && (
          <HStack
            padding={{ horizontal: 16, vertical: 12 }}
            background="rgba(52, 199, 89, 0.10)"
            border={{ style: "rgba(52, 199, 89, 0.25)", width: 0.75 }}
            clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
          >
            <Text font="caption1" bold foregroundColor="#248A3D">
              {successNotice}
            </Text>
          </HStack>
        )}

        {/* Section 1: 快捷导入 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            快捷导入
          </Text>
        </HStack>
        <VStack
          background="#FFFFFF"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(0, 122, 255, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="doc.on.clipboard" font={16} foregroundStyle="#007AFF" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                智能剪贴板识别
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
                自动提取复制文本中的 AK、SK 与实例 ID
              </Text>
            </VStack>
            <Button action={handleSmartPaste} buttonStyle="plain">
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.25)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                spacing={5}
                alignment="center"
                {...liquidGlass(true)}
              >
                <Image systemName="sparkles" font={12} foregroundStyle="#007AFF" />
                <Text font="caption1" bold foregroundColor="#007AFF">一键识别</Text>
              </HStack>
            </Button>
          </HStack>
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 8, bottom: 4 }}>
          复制包含阿里云凭据的文本后轻点此处，自动提取填入下方所有字段。
        </Text>

        {/* Section 2: 访问凭据 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            阿里云访问凭据
          </Text>
        </HStack>
        <VStack
          background="#FFFFFF"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* AccessKey ID */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(255, 149, 0, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="key" font={16} foregroundStyle="#FF9500" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                AccessKey ID
              </Text>
              <Text font="caption2" foregroundColor={ak ? "#8E8E93" : "#007AFF"} lineLimit={1}>
                {ak ? ak : "轻点右侧设置 >"}
              </Text>
            </VStack>
            <Button
              action={() =>
                promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (LTAI 开头)", ak, "LTAI5xxxxxxxxxxx", setAk)
              }
              buttonStyle="plain"
            >
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.22)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                {...liquidGlass(true)}
              >
                <Text font="caption1" bold foregroundColor="#007AFF">
                  {ak ? "修改" : "输入"}
                </Text>
              </HStack>
            </Button>
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* AccessKey Secret */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(255, 59, 48, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="lock" font={16} foregroundStyle="#FF3B30" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                AccessKey Secret
              </Text>
              <Text font="caption2" foregroundColor={sk ? "#248A3D" : "#007AFF"} lineLimit={1}>
                {sk ? "••••••••••••••••••••••••••••" : "轻点右侧设置 >"}
              </Text>
            </VStack>
            <Button
              action={() =>
                promptField("设置 AccessKey Secret", "请输入阿里云 AccessKey Secret", sk, "您的 Secret Key", setSk)
              }
              buttonStyle="plain"
            >
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.22)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                {...liquidGlass(true)}
              >
                <Text font="caption1" bold foregroundColor="#007AFF">
                  {sk ? "修改" : "输入"}
                </Text>
              </HStack>
            </Button>
          </HStack>
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 8, bottom: 4 }}>
          凭据仅加密存储于您 iPhone 本机的隔离沙盒内，绝不上云或外泄。
        </Text>

        {/* Section 3: 目标实例与地域 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            目标 ECS 实例
          </Text>
        </HStack>
        <VStack
          background="#FFFFFF"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* ECS 实例 ID */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(52, 199, 89, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="server.rack" font={16} foregroundStyle="#34C759" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                ECS 实例 ID
              </Text>
              <Text font="caption2" foregroundColor={ecsId ? "#8E8E93" : "#007AFF"} lineLimit={1}>
                {ecsId ? ecsId : "未设置 (如 i-j6c...)"}
              </Text>
            </VStack>
            <Button
              action={() =>
                promptField("设置 ECS 实例 ID", "请输入您要控制的 ECS 实例 ID", ecsId, "i-xxxxxxxxxxxx", setEcsId)
              }
              buttonStyle="plain"
            >
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.22)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                {...liquidGlass(true)}
              >
                <Text font="caption1" bold foregroundColor="#007AFF">
                  {ecsId ? "修改" : "输入"}
                </Text>
              </HStack>
            </Button>
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* ECS 地域 */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(88, 86, 214, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="globe.asia.australia" font={16} foregroundStyle="#5856D6" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                ECS 所在地域
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
                {region || "cn-hongkong"}
              </Text>
            </VStack>
            <Button
              action={() =>
                promptField("设置 ECS 地域", "如 cn-hongkong, cn-hangzhou, cn-shanghai, ap-southeast-1 等", region, "cn-hongkong", setRegion)
              }
              buttonStyle="plain"
            >
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.22)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                {...liquidGlass(true)}
              >
                <Text font="caption1" bold foregroundColor="#007AFF">
                  修改
                </Text>
              </HStack>
            </Button>
          </HStack>
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 8, bottom: 4 }}>
          确保 Region ID 与 ECS 实例所在的物理地域一致。
        </Text>

        {/* Section 4: 流量风控策略 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            流量风控策略
          </Text>
        </HStack>
        <VStack
          background="#FFFFFF"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* CDT 警戒阈值 */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(175, 82, 222, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="speedometer" font={16} foregroundStyle="#AF52DE" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                CDT 流量警戒阈值
              </Text>
              <Text font="caption2" foregroundColor="#FF9500">
                {threshold || "180"} GB / 月
              </Text>
            </VStack>
            <Button
              action={() =>
                promptField("设置 CDT 流量警戒阈值 (GB)", "输入当月出网流量警戒值", threshold, "180", setThreshold)
              }
              buttonStyle="plain"
            >
              <HStack
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.22)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                {...liquidGlass(true)}
              >
                <Text font="caption1" bold foregroundColor="#007AFF">
                  修改
                </Text>
              </HStack>
            </Button>
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* 自动熔断关机开关 */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(0, 199, 190, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="shield.lefthalf.filled" font={16} foregroundStyle="#00C7BE" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundColor="#1C1C1E">
                超额自动关机防扣费
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
                当出网流量达到阈值时自动停止 ECS
              </Text>
            </VStack>
            <Toggle
              isOn={autoStop}
              onToggle={() => setAutoStop(!autoStop)}
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 8, bottom: 16 }}>
          当月 CDT 出网流量达到警戒线时，小组件与控制台将自动触发关机以防超额产生账单。
        </Text>

        {/* 底部保存按钮 (Apple iOS 26 Liquid Glass Capsule) */}
        <Button
          action={handleSave}
          buttonStyle="plain"
          frame={{ maxWidth: Infinity, height: 50 }}
        >
          <HStack
            frame={{ maxWidth: Infinity, height: 50 }}
            background="#007AFF"
            border={{ style: "rgba(255, 255, 255, 0.35)", width: 1 }}
            clipShape={{ type: "capsule" }}
            shadow={{ color: "rgba(0, 122, 255, 0.32)", radius: 10, x: 0, y: 3 }}
            alignment="center"
            spacing={8}
            {...liquidGlass(true)}
          >
            <Image systemName="checkmark.circle.fill" font={17} foregroundStyle="#FFFFFF" />
            <Text font="headline" bold foregroundColor="#FFFFFF">
              保存配置并返回控制台
            </Text>
          </HStack>
        </Button>
      </VStack>
    </ScrollView>
  )
}

// ==================== 7. 控制台仪表盘主视图 (Apple iOS 26 Liquid Glass System) ====================

function AppDashboard() {
  const [config, setConfig] = useState<AppConfig>(loadSavedConfig())
  const [showSettings, setShowSettings] = useState(!isConfigReady(config))
  const [data, setData] = useState<MonitorData | null>(null)
  const [loading, setLoading] = useState(false)
  const [btnLoading, setBtnLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const refresh = useCallback(
    async (cfg: AppConfig = config) => {
      if (!isConfigReady(cfg)) {
        setShowSettings(true)
        return
      }
      setLoading(true)
      setErrorMsg(null)
      try {
        const res = await fetchMonitorData(cfg)
        setData(res)
      } catch (e: any) {
        setErrorMsg(e?.message || "网络请求失败，请检查配置")
      } finally {
        setLoading(false)
      }
    },
    [config]
  )

  useEffect(() => {
    if (isConfigReady(config)) {
      refresh(config)
    }
  }, [])

  const handleToggle = async (action: "start" | "stop") => {
    setBtnLoading(true)
    try {
      await toggleECS(action, config)
      await refresh(config)
    } catch (e: any) {
      setErrorMsg("操作失败: " + e?.message)
    } finally {
      setBtnLoading(false)
    }
  }

  // 二次确认关机弹窗防误触！
  const confirmStop = async () => {
    if (typeof Dialog !== "undefined" && Dialog.actionSheet) {
      const selectedIndex = await Dialog.actionSheet({
        title: "⚠️ 确认停止 ECS 实例？",
        message: `实例 ID: ${config.ecsInstanceId}\n\n停止后服务器将立即断网下线，所有正在运行的网站与服务将暂停访问。确定关机吗？`,
        cancelButton: true,
        actions: [
          {
            label: "确认停止实例 (关机)",
            destructive: true
          }
        ]
      })
      if (selectedIndex === 0) {
        await handleToggle("stop")
      }
    } else {
      await handleToggle("stop")
    }
  }

  if (showSettings) {
    return (
      <NavigationStack>
        <SettingsComponent
          currentConfig={config}
          onSave={newCfg => {
            setConfig(newCfg)
            setShowSettings(false)
            refresh(newCfg)
          }}
          onCancel={() => setShowSettings(false)}
        />
      </NavigationStack>
    )
  }

  const isRunning = data?.ecsStatus === "Running"

  return (
    <NavigationStack>
      <ScrollView
        background="#F2F2F7"
        showsIndicators={false}
        safeAreaPadding={{ bottom: true }}
      >
        <VStack
          alignment="leading"
          spacing={14}
          padding={{ horizontal: 16, top: 12, bottom: 20 }}
        >
          {/* 顶部标题与设置入口 */}
          <HStack alignment="center" padding={{ horizontal: 4, bottom: 2 }}>
            <HStack spacing={8} alignment="center">
              <ZStack
                frame={{ width: 32, height: 32 }}
                background="rgba(0, 122, 255, 0.10)"
                clipShape={{ type: "capsule" }}
              >
                <Image systemName="cloud.fill" font={16} foregroundStyle="#007AFF" />
              </ZStack>
              <Text font="title3" bold foregroundColor="#1C1C1E">
                阿里云 CDT 智控台
              </Text>
            </HStack>
            <Spacer />
            <Button
              action={() => setShowSettings(true)}
              buttonStyle="plain"
              accessibilityLabel="设置"
            >
              <HStack
                spacing={5}
                padding={{ horizontal: 12, vertical: 6 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.25)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                alignment="center"
                {...liquidGlass(true)}
              >
                <Image systemName="gearshape.fill" font={13} foregroundStyle="#007AFF" />
                <Text font="caption1" bold foregroundColor="#007AFF">设置</Text>
              </HStack>
            </Button>
          </HStack>

          {errorMsg && (
            <HStack
              alignment="top"
              spacing={8}
              padding={{ horizontal: 16, vertical: 12 }}
              background="rgba(255, 59, 48, 0.10)"
              border={{ style: "rgba(255, 59, 48, 0.25)", width: 0.75 }}
              clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
            >
              <Image
                systemName="exclamationmark.triangle.fill"
                font={13}
                foregroundStyle="#FF3B30"
              />
              <Text
                font="caption1"
                bold
                foregroundColor="#FF3B30"
                lineLimit={3}
                frame={{ maxWidth: Infinity, alignment: "leading" }}
              >
                {errorMsg}
              </Text>
            </HStack>
          )}

          {/* Section 1: ECS 实例状态 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
              实例运行状态
            </Text>
            <Spacer />
            <Text font={12} foregroundColor="#8E8E93">
              {config.regionId}
            </Text>
          </HStack>

          {/* 内容容器：纯白不透明（HIG 分层法则，卡片严禁玻璃叠玻璃） */}
          <VStack
            background="#FFFFFF"
            clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
            shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
            spacing={0}
            frame={{ maxWidth: Infinity, alignment: "leading" }}
          >
            {/* 实例信息行 */}
            <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
              <ZStack
                frame={{ width: 36, height: 36 }}
                background="rgba(52, 199, 89, 0.10)"
                clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
              >
                <Image
                  systemName="server.rack"
                  font={16}
                  foregroundStyle="#34C759"
                />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundColor="#1C1C1E">
                  ECS 云服务器
                </Text>
                <Text font="caption2" foregroundColor="#8E8E93" lineLimit={1}>
                  {config.ecsInstanceId}
                </Text>
              </VStack>
              {/* 运行状态胶囊 (呼吸微光发光圆点 + 淡绿背景深绿字) */}
              <HStack
                padding={{ horizontal: 10, vertical: 5 }}
                background={isRunning ? "rgba(52, 199, 89, 0.10)" : "rgba(142, 142, 147, 0.12)"}
                clipShape={{ type: "capsule" }}
                spacing={6}
                alignment="center"
              >
                <ZStack frame={{ width: 12, height: 12 }} alignment="center">
                  <Circle fill={isRunning ? "rgba(52, 199, 89, 0.28)" : "rgba(142, 142, 147, 0.25)"} frame={{ width: 12, height: 12 }} />
                  <Circle fill={isRunning ? "#34C759" : "#8E8E93"} frame={{ width: 6, height: 6 }} />
                </ZStack>
                <Text font={12} bold foregroundColor={isRunning ? "#248A3D" : "#636366"}>
                  {isRunning ? "运行中" : data?.ecsStatus === "Stopped" ? "已停止" : data?.ecsStatus || "加载中"}
                </Text>
              </HStack>
            </HStack>

            <Divider padding={{ leading: 64 }} />

            {/* IP与地域行 */}
            <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
              <ZStack
                frame={{ width: 36, height: 36 }}
                background="rgba(0, 122, 255, 0.10)"
                clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
              >
                <Image systemName="network" font={16} foregroundStyle="#007AFF" />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundColor="#1C1C1E">
                  公网 IP 地址
                </Text>
                <Text font="caption2" foregroundColor={data?.publicIp ? "#007AFF" : "#8E8E93"}>
                  {data?.publicIp || "未分配公网 IP"}
                </Text>
              </VStack>
            </HStack>

            <Divider padding={{ horizontal: 16 }} />

            {/* 开关机控制按钮行 (Apple iOS 26 Liquid Glass Capsules) */}
            <HStack
              spacing={12}
              padding={{ horizontal: 16, vertical: 14 }}
              frame={{ maxWidth: "infinity", alignment: "center" }}
            >
              {/* 停止实例按钮：运行中为淡红微光液态玻璃胶囊，停止时为幽灵按钮 */}
              <Button
                action={confirmStop}
                disabled={!isRunning || btnLoading}
                buttonStyle="plain"
                frame={{
                  minWidth: 132,
                  maxWidth: "infinity",
                  minHeight: 44,
                  idealHeight: 44,
                  alignment: "center"
                }}
              >
                <HStack
                  spacing={7}
                  alignment="center"
                  frame={{
                    minWidth: 132,
                    maxWidth: "infinity",
                    minHeight: 44,
                    idealHeight: 44,
                    alignment: "center"
                  }}
                  background={isRunning && !btnLoading ? "rgba(255, 59, 48, 0.09)" : "transparent"}
                  border={
                    isRunning && !btnLoading
                      ? { style: "rgba(255, 59, 48, 0.25)", width: 0.75 }
                      : undefined
                  }
                  clipShape={{ type: "capsule" }}
                  shadow={
                    isRunning && !btnLoading
                      ? { color: "rgba(255, 59, 48, 0.15)", radius: 6, x: 0, y: 2 }
                      : undefined
                  }
                  {...(isRunning && !btnLoading ? liquidGlass(true) : {})}
                >
                  <Image
                    systemName="power"
                    font={15}
                    fontWeight="bold"
                    foregroundStyle={isRunning && !btnLoading ? "#FF3B30" : "#C7C7CC"}
                  />
                  <Text
                    font="subheadline"
                    bold={isRunning && !btnLoading}
                    foregroundColor={isRunning && !btnLoading ? "#FF3B30" : "#C7C7CC"}
                    lineLimit={1}
                    minScaleFactor={0.78}
                    allowsTightening={true}
                  >
                    {btnLoading ? "处理中..." : "停止实例"}
                  </Text>
                </HStack>
              </Button>

              {/* 启动实例按钮：已开机时为极简灰色幽灵按钮，已关机时激活翠绿液态玻璃胶囊 */}
              <Button
                action={() => handleToggle("start")}
                disabled={isRunning || btnLoading}
                buttonStyle="plain"
                frame={{
                  minWidth: 132,
                  maxWidth: "infinity",
                  minHeight: 44,
                  idealHeight: 44,
                  alignment: "center"
                }}
              >
                <HStack
                  spacing={7}
                  alignment="center"
                  frame={{
                    minWidth: 132,
                    maxWidth: "infinity",
                    minHeight: 44,
                    idealHeight: 44,
                    alignment: "center"
                  }}
                  background={!isRunning && !btnLoading ? "rgba(52, 199, 89, 0.12)" : "transparent"}
                  border={
                    !isRunning && !btnLoading
                      ? { style: "rgba(52, 199, 89, 0.28)", width: 0.75 }
                      : undefined
                  }
                  clipShape={{ type: "capsule" }}
                  shadow={
                    !isRunning && !btnLoading
                      ? { color: "rgba(52, 199, 89, 0.16)", radius: 6, x: 0, y: 2 }
                      : undefined
                  }
                  {...(!isRunning && !btnLoading ? liquidGlass(true) : {})}
                >
                  <Image
                    systemName="play"
                    font={14}
                    fontWeight="bold"
                    foregroundStyle={!isRunning && !btnLoading ? "#248A3D" : "#C7C7CC"}
                  />
                  <Text
                    font="subheadline"
                    bold={!isRunning && !btnLoading}
                    foregroundColor={!isRunning && !btnLoading ? "#248A3D" : "#C7C7CC"}
                    lineLimit={1}
                    minScaleFactor={0.78}
                    allowsTightening={true}
                  >
                    {btnLoading ? "处理中..." : "启动实例"}
                  </Text>
                </HStack>
              </Button>
            </HStack>
          </VStack>
          <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 8, bottom: 4 }}>
            为防误触，停止实例需要进行二次弹窗确认后方可执行。
          </Text>

          {/* Section 2: CDT 流量用量卡片 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
              CDT 互联网出网流量
            </Text>
            <Spacer />
            {data && (
              <HStack
                padding={{ horizontal: 8, vertical: 3 }}
                background={data.percentage >= 90 ? "rgba(255, 59, 48, 0.10)" : "rgba(52, 199, 89, 0.10)"}
                clipShape={{ type: "capsule" }}
              >
                <Text font={12} bold foregroundColor={data.percentage >= 90 ? "#FF3B30" : "#248A3D"}>
                  已用 {data.percentage}%
                </Text>
              </HStack>
            )}
          </HStack>

          {/* 内容容器：纯白不透明 */}
          <VStack
            background="#FFFFFF"
            clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
            shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
            spacing={0}
            frame={{ maxWidth: Infinity, alignment: "leading" }}
          >
            {/* 流量主数据 (基线对齐 items-baseline，修复 [object Object] Bug) */}
            <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
              <ZStack
                frame={{ width: 36, height: 36 }}
                background="rgba(175, 82, 222, 0.10)"
                clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
              >
                <Image systemName="arrow.up.and.down" font={16} foregroundStyle="#AF52DE" />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundColor="#1C1C1E">
                  出网用量 / 阈值
                </Text>
                <Text font="caption2" foregroundColor="#8E8E93">
                  当月警戒阈值: {config.trafficThresholdGB} GB
                </Text>
              </VStack>
              {data && (
                <VStack alignment="trailing" spacing={2}>
                  <HStack alignment="lastTextBaseline" spacing={4}>
                    <Text font={28} bold foregroundColor="#1C1C1E">
                      {data.totalGB.toFixed(2)}
                    </Text>
                    <Text font={14} bold foregroundColor="#1C1C1E">
                      GB
                    </Text>
                  </HStack>
                  <Text font={12} foregroundColor="#8E8E93">
                    / {data.thresholdGB} GB
                  </Text>
                </VStack>
              )}
            </HStack>

            {/* 加粗圆角进度条 (高度 8px，左右内边距对齐) */}
            {data && (
              <VStack padding={{ horizontal: 16, top: 2, bottom: 16 }}>
                <ProgressView
                  value={Math.max(0.01, Math.min(1.0, data.percentage / 100))}
                  tint={data.color as any}
                  frame={{ height: 8 }}
                />
              </VStack>
            )}

            <Divider padding={{ horizontal: 16 }} />

            {/* 三列指标卡片 (通透布局，去灰底，数值加粗大字号，内边距 16px) */}
            {data ? (
              <HStack padding={{ horizontal: 16, vertical: 16 }} alignment="center">
                {/* 剩余可用 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundColor="#8E8E93">
                    剩余可用
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundColor="#007AFF">
                      {data.remainingGB.toFixed(1)}
                    </Text>
                    <Text font={12} bold foregroundColor="#007AFF">
                      GB
                    </Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 28 }} />

                {/* 距结算重置 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundColor="#8E8E93">
                    距结算重置
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundColor="#1C1C1E">
                      {data.daysRemaining}
                    </Text>
                    <Text font={12} bold foregroundColor="#8E8E93">
                      天
                    </Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 28 }} />

                {/* 建议日均 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundColor="#8E8E93">
                    建议日均
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundColor={data.color}>
                      &lt; {data.dailyBudgetGB}
                    </Text>
                    <Text font={12} bold foregroundColor={data.color}>
                      GB
                    </Text>
                  </HStack>
                </VStack>
              </HStack>
            ) : (
              <HStack padding={16} alignment="center">
                <Text font="caption2" foregroundColor="#8E8E93">
                  正在同步阿里云最新用量数据...
                </Text>
              </HStack>
            )}
          </VStack>
          <HStack alignment="top" spacing={8} padding={{ leading: 8, bottom: 4 }}>
            <Image systemName="shield.fill" font={12} foregroundStyle="#8E8E93" />
            <Text
              font={12}
              foregroundColor="#8E8E93"
              lineLimit={3}
              frame={{ maxWidth: Infinity, alignment: "leading" }}
            >
              自动熔断：当出网流量达到 {config.trafficThresholdGB} GB 时将自动停止 ECS 实例防止产生账单。
            </Text>
          </HStack>

          {/* 刷新控制台操作按钮 (Liquid Glass Capsule) */}
          <HStack padding={{ top: 8, bottom: 16 }} alignment="center">
            <Spacer />
            <Button
              action={() => refresh(config)}
              disabled={loading}
              buttonStyle="plain"
            >
              <HStack
                spacing={6}
                padding={{ horizontal: 16, vertical: 8 }}
                background="rgba(0, 122, 255, 0.10)"
                border={{ style: "rgba(0, 122, 255, 0.25)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                alignment="center"
                {...liquidGlass(true)}
              >
                <Image
                  systemName="arrow.clockwise"
                  font={13}
                  fontWeight="bold"
                  foregroundStyle="#007AFF"
                />
                <Text font="subheadline" bold foregroundColor="#007AFF">
                  {loading ? "同步数据中..." : "刷新控制台数据"}
                </Text>
              </HStack>
            </Button>
            <Spacer />
          </HStack>
        </VStack>
      </ScrollView>
    </NavigationStack>
  )
}

// ==================== 8. 执行分流 (Widget 还是 App) ====================

async function main() {
  const isWidget = typeof Widget !== "undefined" && Boolean(Widget?.family)

  if (isWidget) {
    try {
      const config = loadSavedConfig()
      if (!isConfigReady(config)) {
        Widget.present(<NotConfiguredWidget />)
        return
      }
      const data = await fetchMonitorData(config)
      if (Widget.family === "accessoryInline") {
        Widget.present(<AccessoryInlineWidget data={data} />)
      } else if (Widget.family === "accessoryRectangular") {
        Widget.present(<AccessoryRectangularWidget data={data} />)
      } else if (Widget.family === "systemLarge") {
        Widget.present(<LargeWidget data={data} />)
      } else if (Widget.family === "systemMedium") {
        Widget.present(<MediumWidget data={data} />)
      } else {
        Widget.present(<SmallWidget data={data} />)
      }
    } catch (err: any) {
      Widget.present(
        <VStack>
          <Text font="caption2" foregroundColor="#FF453A">
            {err?.message || "拉取失败"}
          </Text>
        </VStack>
      )
    }
  } else {
    await Navigation.present({
      element: <AppDashboard />
    })
    Script.exit()
  }
}

main()
