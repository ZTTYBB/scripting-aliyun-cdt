/**
 * ============================================================================
 * 阿里云 CDT 流量监控与 ECS 智控【桌面小组件专属脚本】
 * 文件名: widget.tsx
 * ============================================================================
 * 通用版特性：
 * 1. 自动从 Scripting Storage 读取用户配置，绝无硬编码凭据
 * 2. 若用户尚未配置，小组件优雅提示用户在 App 内打开脚本进行配置
 * 3. 兼容 iOS 16/17/18 主屏幕（小号/中号/大号）及锁屏小组件
 * 4. 纯 TS 内置 HMAC-SHA1 签名与 POP API 客户端
 */

import {
  Widget,
  VStack,
  HStack,
  ZStack,
  Text,
  Spacer
} from "scripting"

// ==================== 1. 本地存储配置读取 ====================

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
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  ecsStatus: "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"
  publicIp?: string
  color: string
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
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))

  // 2. 查询 ECS 状态
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

  // 3. 超额自动熔断保护：≥ 阈值且正在运行时自动停止
  if (config.autoStopOnExceed && totalGB >= thresholdGB && ecsStatus === "Running") {
    await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, "StopInstance", "2014-05-26", config, {
      InstanceId: config.ecsInstanceId.trim(),
      ForceStop: false
    })
    ecsStatus = "Stopping"
  }

  // 4. 重置日推算
  const now = new Date()
  const currentDay = now.getDate()
  const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()
  const daysRemaining = Math.max(1, lastDay - currentDay + 1)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(1)

  const color = percentage >= 90 ? "#FF453A" : percentage >= 70 ? "#FF9F0A" : "#30D158"

  return {
    totalGB,
    thresholdGB,
    remainingGB,
    percentage,
    daysRemaining,
    dailyBudgetGB,
    ecsStatus,
    publicIp,
    color
  }
}

// ==================== 4. 小组件渲染视图 ====================

/** 未配置提示视图 */
function NotConfiguredWidgetView() {
  return (
    <VStack alignment="leading" spacing={4}>
      <Text font="headline" bold foregroundColor="#FF9F0A">
        ⚙️ 待配置
      </Text>
      <Text font="caption2" foregroundColor="#8E8E93">
        请在 Scripting App 中打开此脚本，填入您的阿里云 AK/SK 与 ECS 实例信息。
      </Text>
      <Spacer />
      <Text font="caption2" bold foregroundColor="#0A84FF">
        轻点进入配置 &gt;
      </Text>
    </VStack>
  )
}

/** 小号小组件 (systemSmall) */
function SmallWidgetView({ data }: { data: WidgetData }) {
  const isRunning = data.ecsStatus === "Running"

  return (
    <VStack alignment="leading" spacing={6}>
      <HStack>
        <Text font="caption2" foregroundColor="#8E8E93">
          ☁️ CDT 流量
        </Text>
        <Spacer />
        <Text font="caption2">
          {isRunning ? "🟢" : "🔴"} {isRunning ? "运行中" : "已停止"}
        </Text>
      </HStack>

      <Spacer />

      <VStack alignment="leading" spacing={2}>
        <HStack alignment="bottom" spacing={2}>
          <Text font="title" bold foregroundColor={data.color}>
            {data.totalGB.toFixed(1)}
          </Text>
          <Text font="footnote" foregroundColor="#8E8E93">
            / {data.thresholdGB} GB
          </Text>
        </HStack>
        <Text font="caption2" foregroundColor="#8E8E93">
          已用 {data.percentage}% · 剩 {data.remainingGB.toFixed(1)}G
        </Text>
      </VStack>

      {/* 进度条 */}
      <ZStack alignment="leading">
        <HStack
          frame={{ height: 5, maxWidth: "infinity" }}
          background="rgba(142, 142, 147, 0.25)"
          cornerRadius={2.5}
        />
        <HStack
          frame={{
            height: 5,
            width: `${Math.max(4, Math.min(100, data.percentage))}%`
          }}
          background={data.color}
          cornerRadius={2.5}
        />
      </ZStack>

      <Spacer />

      <HStack>
        <Text font="caption2" foregroundColor="#8E8E93">
          距重置:
        </Text>
        <Spacer />
        <Text font="caption2" bold foregroundColor="#0A84FF">
          {data.daysRemaining} 天
        </Text>
      </HStack>
    </VStack>
  )
}

/** 中号小组件 (systemMedium) */
function MediumWidgetView({ data }: { data: WidgetData }) {
  const isRunning = data.ecsStatus === "Running"

  return (
    <VStack alignment="leading" spacing={8}>
      <HStack>
        <Text font="headline" bold>
          ☁️ 阿里云 CDT 监控
        </Text>
        <Spacer />
        <HStack
          padding={{ top: 2, bottom: 2, leading: 6, trailing: 6 }}
          background="rgba(142, 142, 147, 0.15)"
          cornerRadius={6}
          spacing={4}
        >
          <Text font="caption2">{isRunning ? "🟢" : "🔴"}</Text>
          <Text font="caption2" bold foregroundColor={isRunning ? "#30D158" : "#8E8E93"}>
            ECS {isRunning ? "运行中" : "已关机"}
          </Text>
        </HStack>
      </HStack>

      <HStack alignment="bottom" spacing={8}>
        <Text font="largeTitle" bold foregroundColor={data.color}>
          {data.totalGB.toFixed(1)}
        </Text>
        <Text font="subheadline" foregroundColor="#8E8E93" padding={{ bottom: 4 }}>
          GB / {data.thresholdGB} GB
        </Text>
        <Spacer />
        <VStack alignment="trailing" spacing={2}>
          <Text font="footnote" bold foregroundColor={data.color}>
            已使用 {data.percentage}%
          </Text>
          <Text font="caption2" foregroundColor="#8E8E93">
            剩余可用: {data.remainingGB.toFixed(1)} GB
          </Text>
        </VStack>
      </HStack>

      {/* 进度条 */}
      <ZStack alignment="leading">
        <HStack
          frame={{ height: 6, maxWidth: "infinity" }}
          background="rgba(142, 142, 147, 0.2)"
          cornerRadius={3}
        />
        <HStack
          frame={{
            height: 6,
            width: `${Math.max(3, Math.min(100, data.percentage))}%`
          }}
          background={data.color}
          cornerRadius={3}
        />
      </ZStack>

      <Spacer />

      <HStack alignment="center">
        <Text font="caption2" foregroundColor="#8E8E93">
          距结算重置:
        </Text>
        <Text font="caption2" bold foregroundColor="#0A84FF">
          {data.daysRemaining}天
        </Text>
        <Text font="caption2" foregroundColor="#8E8E93">
          · 建议日均:
        </Text>
        <Text font="caption2" bold foregroundColor={data.color}>
          &lt; {data.dailyBudgetGB}G
        </Text>
        <Spacer />
        {data.publicIp && (
          <Text font="caption2" foregroundColor="#8E8E93">
            IP: {data.publicIp}
          </Text>
        )}
      </HStack>
    </VStack>
  )
}

/** 锁屏矩形小组件 (accessoryRectangular) */
function AccessoryRectangularView({ data }: { data: WidgetData }) {
  const isRunning = data.ecsStatus === "Running"

  return (
    <VStack alignment="leading" spacing={2}>
      <Text font="caption2" bold>
        ☁️ CDT: {data.totalGB.toFixed(1)}G / {data.thresholdGB}G ({data.percentage}%)
      </Text>
      <Text font="caption2">
        {isRunning ? "🟢 运行中" : "🔴 已停止"} · 剩 {data.remainingGB.toFixed(1)}G
      </Text>
      <Text font="caption2" foregroundColor="#8E8E93">
        重置倒计时: {data.daysRemaining} 天
      </Text>
    </VStack>
  )
}

// ==================== 5. 主执行入口 ====================

async function main() {
  try {
    const config = loadSavedConfig()

    // 若未配置，渲染引导提示
    if (!isConfigReady(config)) {
      Widget.present(<NotConfiguredWidgetView />)
      return
    }

    const data = await fetchWidgetData(config)
    const family = Widget.family

    if (family === "accessoryRectangular" || family === "accessoryInline") {
      Widget.present(<AccessoryRectangularView data={data} />)
    } else if (family === "systemMedium" || family === "systemLarge") {
      Widget.present(<MediumWidgetView data={data} />)
    } else {
      Widget.present(<SmallWidgetView data={data} />)
    }
  } catch (err: any) {
    console.error("小组件加载失败:", err)
    Widget.present(
      <VStack alignment="leading" spacing={4}>
        <Text font="caption1" bold foregroundColor="#FF453A">
          ⚠️ 获取失败
        </Text>
        <Text font="caption2" foregroundColor="#8E8E93">
          {err?.message || "网络或凭据错误"}
        </Text>
      </VStack>
    )
  }
}

main()
