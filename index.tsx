/**
 * ============================================================================
 * 阿里云 CDT 流量与 ECS 状态只读控制台 (iOS Scripting Console)
 * 文件名: index.tsx
 * ============================================================================
 * 通用版特性：
 * 1. 零硬编码：完全通过 UI 设置面板录入，自动持久化至本地 Storage
 * 2. 交互式控制台：实时 CDT 流量环/进度条与 ECS 只读状态
 * 3. 完整设置界面：随时修改 AK/SK、地域、ECS 实例 ID 与流量参考线
 * 4. 控制台实时运行日志记录
 */

import {
  Navigation,
  Script,
  NavigationStack,
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
  Toolbar,
  ToolbarItem,
  useState,
  useEffect,
  useCallback
} from "scripting"

// ==================== 1. 本地存储配置管理 ====================

const APP_VERSION = "1.6.0"

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
  outstandingAmount: string
  currency: string
  ecsAmount: string
  eipAmount: string
  cdtAmount: string
  ecsDailyList: DailyExpenseItem[]
  eipDailyList: DailyExpenseItem[]
}

function isBillQueryAvailable(response: any): boolean {
  return Boolean(response?.Data && response?.Success === true && response?.Code === "Success")
}

interface ConsoleData {
  totalGB: number
  thresholdGB: number
  vpsCutoffReferenceGB: number
  cutoffRemainingGB: number
  remainingGB: number
  percentage: number
  daysRemaining: number
  dailyBudgetGB: string
  monthTimeProgress: number
  ecsStatus: "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"
  publicIp?: string
  color: string
  updatedAt?: string | Date
  financialBalance?: AccountBalanceInfo | null
  financialBill?: MonthlyBillInfo | null
  financialBillStatus: "available" | "unavailable"
}

const SNAPSHOT_STORAGE_KEY = "aliyun_cdt_dashboard_cache"
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

async function fetchConsoleData(config: AppConfig): Promise<ConsoleData> {
  // 1. 查询 CDT 流量
  const cdtData = await aliyunRequest<{
    TrafficDetails?: Array<{ Traffic?: number }>
  }>("cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config)

  const details = cdtData.TrafficDetails || []
  const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))

  // 2. 查询 ECS 状态
  const ecsData = await aliyunRequest<{
    Instances?: {
      Instance?: ECSInstanceRecord[]
    }
  }>(`ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
    InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
    RegionId: config.regionId.trim()
  })

  const instance = ecsData.Instances?.Instance?.[0]
  let ecsStatus = (instance?.Status as any) || "Unknown"
  const publicIp = getInstancePublicIp(instance)

  // 3. 纯统计模式：控制台仅只读拉取用量与账单，关机熔断由 VPS 独立守护

  // 4. 重置日与时间进度推算
  const now = new Date()
  const currentDay = now.getDate()
  const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()
  const daysRemaining = Math.max(1, lastDay - currentDay + 1)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(1)
  const monthTimeProgress = Math.min(100, Math.max(1, Number(((currentDay / lastDay) * 100).toFixed(1))))

  // 5. 资产与消费查询 (优雅降级，未授权时不中断主流程)
  let financialBalance: AccountBalanceInfo | null = null
  let financialBill: MonthlyBillInfo | null = null
  let financialBillStatus: "available" | "unavailable" = "unavailable"

  try {
    const balRes = await aliyunRequest<{
      Data?: {
        AvailableAmount?: string
        AvailableCashAmount?: string
        CreditAmount?: string
        Currency?: string
      }
    }>("business.aliyuncs.com", "QueryAccountBalance", "2017-12-14", config).catch(() => null)

    if (balRes?.Data) {
      const cash = parseFloat(balRes.Data.AvailableCashAmount || "0")
      let status: "sufficient" | "low" | "arrears" = "sufficient"
      if (cash <= 0) {
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
    const cycle = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`

    // 1. 优先调用 QueryBillOverview（对齐阿里云控制台账单总览，直接按产品汇算）
    let billItems: Array<{
      PipCode?: string
      ProductCode?: string
      ProductName?: string
      PaymentAmount?: number
      PretaxGrossAmount?: number
      PretaxAmount?: number
      OutstandingAmount?: number
      Currency?: string
    }> = []

    const overviewRes = await aliyunRequest<{
      Data?: {
        Items?: {
          Item?: Array<any>
        }
      }
    }>("business.aliyuncs.com", "QueryBillOverview", "2017-12-14", config, {
      BillingCycle: cycle
    }).catch(() => null)

    if (isBillQueryAvailable(overviewRes)) financialBillStatus = "available"
    if (overviewRes?.Data?.Items?.Item && overviewRes.Data.Items.Item.length > 0) {
      billItems = overviewRes.Data.Items.Item
    } else {
      // 2. 回退调用 QueryAccountBill（带 IsGroupByProduct: true 才能返回产品维度分类）
      const billRes = await aliyunRequest<{
        Data?: {
          Items?: {
            Item?: Array<any>
          }
        }
      }>("business.aliyuncs.com", "QueryAccountBill", "2017-12-14", config, {
        BillingCycle: cycle,
        IsGroupByProduct: true
      }).catch(() => null)

      if (isBillQueryAvailable(billRes)) financialBillStatus = "available"
      if (billRes?.Data?.Items?.Item && billRes.Data.Items.Item.length > 0) {
        billItems = billRes.Data.Items.Item
      }
    }

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
        const gross = Number(it.PretaxGrossAmount || 0)
        // 关键：必须优先取 PretaxAmount（实际应付金额：已扣减抢占式竞价折扣、优惠券，如抢占式单日 ¥0.13，月度 ¥0.40）
        let effective = 0
        if (it.PretaxAmount !== undefined && it.PretaxAmount !== null && it.PretaxAmount !== "") {
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

      // 保留接口返回的零金额；仅在没有可分类产品时使用全产品合计。
      const infrastructureTotal = ecsTotal + eipTotal + cdtTotal
      const finalPayment = hasInfrastructureItems
        ? infrastructureTotal
        : allProductsEffective

      const formatDaily = (amt: number): string => {
        if (amt <= 0) return "0.00"
        if (amt < 0.01) return amt.toFixed(3)
        return amt.toFixed(2)
      }

      // 查询最近日期的每日账单明细；月内数据可能延迟。
      const ecsDailyList: DailyExpenseItem[] = []
      const eipDailyList: DailyExpenseItem[] = []
      const daysCount = Math.min(7, currentDay)

      const dateQueries: Array<{ dateStr: string; displayDate: string; isToday: boolean }> = []
      for (let i = 0; i < daysCount; i++) {
        const d = new Date(now.getFullYear(), now.getMonth(), currentDay - i)
        const yyyy = d.getFullYear()
        const mm = String(d.getMonth() + 1).padStart(2, "0")
        const dd = String(d.getDate()).padStart(2, "0")
        dateQueries.push({
          dateStr: `${yyyy}-${mm}-${dd}`,
          displayDate: `${mm}-${dd}`,
          isToday: i === 0
        })
      }

      try {
        const dailyResults = await Promise.all(
          dateQueries.map(async q => {
            try {
              const dayRes = await aliyunRequest<{
                Data?: {
                  Items?: {
                    Item?: Array<any>
                  }
                }
              }>("business.aliyuncs.com", "QueryAccountBill", "2017-12-14", config, {
                BillingCycle: cycle,
                Granularity: "DAILY",
                BillingDate: q.dateStr,
                IsGroupByProduct: true
              }).catch(() => null)

              const dayItems = dayRes?.Data?.Items?.Item || []
              let dEcs = 0
              let dEip = 0
              for (const it of dayItems) {
                const c = String(it.PipCode || it.ProductCode || "").toLowerCase()
                const n = String(it.ProductName || "")
                const p = Number(it.PaymentAmount || 0)
                const g = Number(it.PretaxGrossAmount || 0)
                // 优先取 PretaxAmount（抢占式实例实际折后金额）
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
                available: isBillQueryAvailable(dayRes)
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
      outstandingAmount: outstanding.toFixed(2),
      currency,
      ecsAmount: ecsTotal.toFixed(2),
      eipAmount: eipTotal.toFixed(2),
      cdtAmount: cdtTotal.toFixed(2),
      ecsDailyList,
      eipDailyList
    }
  } catch {}

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
    monthTimeProgress,
    ecsStatus,
    publicIp,
    color,
    updatedAt: now.toISOString(),
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
    return { label: "已达到 VPS 熔断参考线（仅展示）", color: "systemRed", icon: "exclamationmark.octagon.fill" }
  }
  if (totalGB >= cutoffReferenceGB - 15) {
    return { label: "接近 VPS 熔断参考线（仅展示）", color: "systemOrange", icon: "exclamationmark.circle.fill" }
  }
  if (percentage > monthTimeProgress + 15) {
    return { label: "月用量参考进度超前", color: "systemOrange", icon: "exclamationmark.circle.fill" }
  }
  return { label: "月用量处于本地参考进度内", color: "systemGreen", icon: "checkmark.circle.fill" }
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
    return "RAM 权限不足：请在阿里云访问控制为该 Key 授予 AliyunECSFullAccess 和 CDT 读权限。"
  }
  if (rawMessage.includes("IncorrectInstanceStatus")) {
    return "实例当前状态无法执行此操作，请稍候重试。"
  }
  if (rawMessage.includes("OperationDenied.NoStock")) {
    return "当前地域实例资源库存紧张，无法启动。"
  }
  return rawMessage
}

function splitLogLine(log: string): { time: string; message: string } {
  const match = log.match(/^(\[[^\]]+\])\s*(.*)$/)
  return match ? { time: match[1], message: match[2] } : { time: "", message: log }
}

function logMessageColor(log: string): string {
  if (/错误|失败/.test(log)) return "systemRed"
  if (/成功|完成|已发送/.test(log)) return "systemGreen"
  return "label"
}

// ==================== 4. Apple iOS 26 Liquid Glass 材质与动效系统 ====================

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

// ==================== 5. 设置配置面板视图 (Apple Liquid Glass Controls) ====================

function SettingsActionButton({
  label,
  action,
  accessibilityLabel
}: {
  label: string
  action: () => void
  accessibilityLabel: string
}) {
  return (
    <Button action={action} buttonStyle="plain" accessibilityLabel={accessibilityLabel}>
      <HStack spacing={3} padding={{ horizontal: 8, vertical: 6 }} alignment="center">
        <Text font="caption1" bold foregroundStyle="systemBlue">
          {label}
        </Text>
        <Image systemName="chevron.right" font={10} foregroundStyle="systemBlue" />
      </HStack>
    </Button>
  )
}

function SettingsView({
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
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || 200))
  const [cutoffReference, setCutoffReference] = useState(
    String(currentConfig.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB)
  )
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

  const REGION_PRESETS = [
    { id: "cn-hongkong", label: "🇭🇰 中国香港 (cn-hongkong)" },
    { id: "cn-hangzhou", label: "🇨🇳 华东1 杭州 (cn-hangzhou)" },
    { id: "cn-shanghai", label: "🇨🇳 华东2 上海 (cn-shanghai)" },
    { id: "cn-beijing", label: "🇨🇳 华北2 北京 (cn-beijing)" },
    { id: "cn-shenzhen", label: "🇨🇳 华南1 深圳 (cn-shenzhen)" },
    { id: "ap-southeast-1", label: "🇸🇬 新加坡 (ap-southeast-1)" },
    { id: "ap-northeast-1", label: "🇯🇵 日本东京 (ap-northeast-1)" },
    { id: "us-west-1", label: "🇺🇸 美国硅谷 (us-west-1)" }
  ]

  const handleSelectRegion = async () => {
    if (typeof Dialog !== "undefined" && Dialog.actionSheet) {
      const actions = REGION_PRESETS.map(item => ({
        label: `${item.label}${region === item.id ? " ✓" : ""}`
      }))
      actions.push({ label: "🌐 自定义输入其他地域..." })

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

  const handleSave = () => {
    if (!ak.trim() || !sk.trim() || !ecsId.trim()) {
      setErrorNotice("请填写完整的 AccessKey ID、Secret 与 ECS 实例 ID！")
      return
    }
    const numThreshold = Number(threshold)
    if (!Number.isFinite(numThreshold) || numThreshold <= 0) {
      setErrorNotice("月用量参考值必须是大于 0 的数字。")
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
      resetDayOfMonth: 1
    }
    saveConfigToStorage(newCfg)
    onSave(newCfg)
  }

  return (
    <ScrollView background="systemGray6" showsIndicators={false}>
      <VStack
        alignment="leading"
        spacing={12}
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
                <Image systemName="chevron.backward" font={13} fontWeight="bold" foregroundStyle="systemBlue" />
                <Text font="caption1" bold foregroundStyle="systemBlue">返回</Text>
              </HStack>
            </Button>
          ) : (
            <Spacer frame={{ width: 60 }} />
          )}
          <Spacer />
          <Text font="headline" bold foregroundStyle="label">
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
              <Text font="caption1" bold foregroundStyle="systemBlue">保存</Text>
            </HStack>
          </Button>
        </HStack>

        {/* 提示横幅 (统一使用 Apple 原生 SF Symbols 矢量图标) */}
        {errorNotice && (
          <HStack
            alignment="top"
            spacing={8}
            padding={{ horizontal: 16, vertical: 12 }}
            background="rgba(255, 59, 48, 0.10)"
            border={{ style: "rgba(255, 59, 48, 0.25)", width: 0.75 }}
            clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
          >
            <Image systemName="exclamationmark.triangle.fill" font={13} foregroundStyle="systemRed" />
            <Text font="caption1" bold foregroundStyle="systemRed" lineLimit={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              {errorNotice}
            </Text>
          </HStack>
        )}
        {successNotice && (
          <HStack
            alignment="top"
            spacing={8}
            padding={{ horizontal: 16, vertical: 12 }}
            background="rgba(52, 199, 89, 0.10)"
            border={{ style: "rgba(52, 199, 89, 0.25)", width: 0.75 }}
            clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
          >
            <Image systemName="checkmark.circle.fill" font={13} foregroundStyle="systemGreen" />
            <Text font="caption1" bold foregroundStyle="systemGreen" lineLimit={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              {successNotice}
            </Text>
          </HStack>
        )}

        {/* Section 1: 快捷导入 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
            快捷导入
          </Text>
        </HStack>
        <VStack
          background="systemBackground"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(0, 122, 255, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="doc.on.clipboard" font={16} foregroundStyle="systemBlue" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                智能剪贴板识别
              </Text>
              <Text font="caption2" foregroundStyle="secondaryLabel">
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
                <Image systemName="sparkles" font={12} foregroundStyle="systemBlue" />
                <Text font="caption1" bold foregroundStyle="systemBlue">一键识别</Text>
              </HStack>
            </Button>
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
          复制包含阿里云凭据的文本后轻点此处，自动提取填入下方所有字段。
        </Text>

        {/* Section 2: 访问凭据 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
            阿里云访问凭据
          </Text>
        </HStack>
        <VStack
          background="systemBackground"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* AccessKey ID */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(255, 149, 0, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="key" font={16} foregroundStyle="systemOrange" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                AccessKey ID
              </Text>
              <Text font="caption2" foregroundStyle={ak ? "secondaryLabel" : "systemBlue"} lineLimit={1}>
                {ak ? ak : "轻点右侧设置 >"}
              </Text>
            </VStack>
            <SettingsActionButton
              label={ak ? "修改" : "设置"}
              accessibilityLabel="设置 AccessKey ID"
              action={() =>
                promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (LTAI 开头)", ak, "LTAI...", setAk)
              }
            />
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* AccessKey Secret */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(255, 59, 48, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="lock" font={16} foregroundStyle="systemRed" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                AccessKey Secret
              </Text>
              <Text font="caption2" foregroundStyle={sk ? "systemGreen" : "systemBlue"} lineLimit={1}>
                {sk ? "已设置" : "轻点右侧设置"}
              </Text>
            </VStack>
            <SettingsActionButton
              label={sk ? "修改" : "设置"}
              accessibilityLabel="设置 AccessKey Secret"
              action={() =>
                promptField("设置 AccessKey Secret", "请输入阿里云 AccessKey Secret", sk, "您的 Secret Key", setSk)
              }
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
          凭据保存在 Scripting 本机 Storage；此项目未实现应用层加密，请使用最小权限 RAM 凭据。
        </Text>

        {/* Section 3: 目标实例与地域 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
            目标 ECS 实例
          </Text>
        </HStack>
        <VStack
          background="systemBackground"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* ECS 实例 ID */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(52, 199, 89, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="server.rack" font={16} foregroundStyle="systemGreen" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                ECS 实例 ID
              </Text>
              <Text font="caption2" foregroundStyle={ecsId ? "secondaryLabel" : "systemBlue"} lineLimit={1}>
                {ecsId ? ecsId : "未设置 (如 i-j6c...)"}
              </Text>
            </VStack>
            <SettingsActionButton
              label={ecsId ? "修改" : "设置"}
              accessibilityLabel="设置 ECS 实例 ID"
              action={() =>
                promptField("设置 ECS 实例 ID", "请输入您要控制的 ECS 实例 ID", ecsId, "i-xxxxxxxxxxxx", setEcsId)
              }
            />
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* ECS 地域 */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(88, 86, 214, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="globe.asia.australia" font={16} foregroundStyle="systemIndigo" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                ECS 所在地域
              </Text>
              <Text font="caption2" foregroundStyle="secondaryLabel">
                {region || "cn-hongkong"}
              </Text>
            </VStack>
            <SettingsActionButton
              label="选择"
              accessibilityLabel="设置 ECS 地域"
              action={handleSelectRegion}
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
          确保 Region ID 与 ECS 实例所在的物理地域一致。
        </Text>

        {/* Section 4: 只读流量参考值 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
            流量参考值
          </Text>
        </HStack>
        <VStack
          background="systemBackground"
          clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
          shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
          spacing={0}
        >
          {/* 本地月用量参考值 */}
          <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(175, 82, 222, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="speedometer" font={16} foregroundStyle="systemPurple" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                本地月用量参考值
              </Text>
              <Text font="caption2" foregroundStyle="systemOrange">
                {threshold || "200"} GB / 月
              </Text>
            </VStack>
            <SettingsActionButton
              label="修改"
              accessibilityLabel="设置本地月用量参考值"
              action={() =>
                promptField("本地月用量参考值 (GB)", "仅作本地用量参考，不代表阿里云账号完整免费额度余额，也不会触发 ECS 操作", threshold, "200", setThreshold)
              }
            />
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* VPS 熔断线仅供本地对照 */}
          <HStack padding={{ horizontal: 16, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack
              frame={{ width: 36, height: 36 }}
              background="rgba(0, 199, 190, 0.10)"
              clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
            >
              <Image systemName="shield.lefthalf.filled" font={16} foregroundStyle="systemTeal" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                VPS 熔断参考线
              </Text>
              <Text font="caption2" foregroundStyle="secondaryLabel">
                {cutoffReference} GB · 仅展示，不控制 ECS
              </Text>
            </VStack>
            <SettingsActionButton
              label="修改"
              accessibilityLabel="设置 VPS 熔断参考线"
              action={() =>
                promptField("VPS 熔断参考线 (GB)", "按 VPS 脚本阈值手动填写；此值只用于手机告警，不会同步或关机", cutoffReference, cutoffReference, setCutoffReference)
              }
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 16 }}>
          VPS 独立负责保活与熔断。手机只查询阿里云；此处的参考线不会与 VPS 同步。
        </Text>

        {/* 底部保存按钮 (Apple iOS 26 Liquid Glass Capsule) */}
        <Button
          action={handleSave}
          buttonStyle="plain"
          accessibilityLabel="保存配置并返回控制台"
          frame={{ maxWidth: Infinity, height: 50 }}
        >
          <HStack
            frame={{ maxWidth: Infinity, height: 50 }}
            background="systemBlue"
            border={{ style: "rgba(255, 255, 255, 0.35)", width: 1 }}
            clipShape={{ type: "capsule" }}
            shadow={{ color: "rgba(0, 122, 255, 0.32)", radius: 10, x: 0, y: 3 }}
            alignment="center"
            spacing={8}
            {...liquidGlass(true)}
          >
            <Image systemName="checkmark.circle.fill" font={17} foregroundStyle="#FFFFFF" />
            <Text font="headline" bold foregroundStyle="#FFFFFF">
              保存并返回
            </Text>
          </HStack>
        </Button>

        {/* 版本号与构建信息 */}
        <VStack alignment="center" spacing={4} padding={{ top: 16, bottom: 24 }}>
          <HStack spacing={6} alignment="center">
            <Image systemName="checkmark.shield.fill" font={12} foregroundStyle="systemGreen" />
            <Text font={13} bold foregroundStyle="secondaryLabel">
              阿里云 CDT 监控 v{APP_VERSION}
            </Text>
          </HStack>
          <Text font={11} foregroundStyle="tertiaryLabel">
            BSS 账单查询 · Build 2026.09.23
          </Text>
        </VStack>
      </VStack>
    </ScrollView>
  )
}

// ==================== 6. 控制台仪表盘主视图 (Apple iOS 26 Liquid Glass System) ====================

function getCachedConsoleSnapshot(): { data: ConsoleData | null; lastUpdated: Date | null } {
  try {
    if (typeof Storage !== "undefined" && Storage?.get) {
      const raw = Storage.get(SNAPSHOT_STORAGE_KEY)
      if (raw) {
        const parsed: ConsoleData = typeof raw === "string" ? JSON.parse(raw) : raw
        if (parsed.financialBillStatus !== "available") {
          parsed.financialBillStatus = "unavailable"
        }
        for (const list of [parsed.financialBill?.ecsDailyList, parsed.financialBill?.eipDailyList]) {
          for (const item of list || []) {
            if (typeof item.available !== "boolean") item.available = false
          }
        }
        const ts = parsed.updatedAt ? new Date(parsed.updatedAt) : null
        return { data: parsed, lastUpdated: ts }
      }
    }
  } catch {}
  return { data: null, lastUpdated: null }
}

function ConsoleView() {
  const [config, setConfig] = useState<AppConfig>(loadSavedConfig())
  const [showSettings, setShowSettings] = useState(!isConfigReady(config))
  const initialCache = getCachedConsoleSnapshot()
  const [data, setData] = useState<ConsoleData | null>(initialCache.data)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(initialCache.lastUpdated)
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])
  const [isPrivacy, setIsPrivacy] = useState<boolean>(() => {
    try {
      return typeof Storage !== "undefined" && Storage.get(PRIVACY_STORAGE_KEY) === "true"
    } catch {
      return false
    }
  })
  const [isCopied, setIsCopied] = useState(false)

  const appendLog = (msg: string) => {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [`[${time}] ${msg}`, ...prev.slice(0, 7)])
  }

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
      appendLog(`已复制公网 IP: ${data.publicIp}`)
    } catch {}
  }

  const handleShowEcsDaily = async () => {
    try {
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
    } catch {}

    const list = data?.financialBill?.ecsDailyList || []
    const total = data?.financialBillStatus === "unavailable"
      ? "暂不可用"
      : isPrivacy
        ? "****"
        : `¥${data?.financialBill?.ecsAmount || "0.00"}`
    const lines = list.map(item => {
      const amt = item.available === false ? "—" : isPrivacy ? "****" : `¥${item.amount}`
      let tag = ""
      if (item.available === false) {
        tag = " (查询失败)"
      } else if (item.isToday) {
        tag = parseFloat(item.amount) > 0 ? " (今日查询结果)" : " (当前查询为0，非最终账单)"
      } else {
        tag = parseFloat(item.amount) > 0 ? " (查询到的费用)" : " (当前查询为0，非最终账单)"
      }
      return `📅 ${item.date}: ${amt}${tag}`
    })

    const msg = [
      `ECS 实例 ID: ${config.ecsInstanceId}`,
      `本月账单查询结果: ${total}`,
      "",
      "【每日账单查询结果（可能延迟）】",
      lines.length > 0 ? lines.join("\n") : "暂无每日明细数据",
      "",
      data?.financialBillStatus === "unavailable"
        ? "账单接口暂不可用，请检查 BSS 权限或稍后刷新。"
        : "月内账单数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({
        title: "🖥️ ECS 实例每日费用明细",
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
    const total = data?.financialBillStatus === "unavailable"
      ? "暂不可用"
      : isPrivacy
        ? "****"
        : `¥${data?.financialBill?.eipAmount || "0.00"}`
    const lines = list.map(item => {
      const amt = item.available === false ? "—" : isPrivacy ? "****" : `¥${item.amount}`
      let tag = ""
      if (item.available === false) {
        tag = " (查询失败)"
      } else if (item.isToday) {
        tag = parseFloat(item.amount) > 0 ? " (今日查询结果)" : " (当前查询为0，非最终账单)"
      } else {
        tag = parseFloat(item.amount) > 0 ? " (查询到的费用)" : " (当前查询为0，非最终账单)"
      }
      return `📅 ${item.date}: ${amt}${tag}`
    })

    const msg = [
      `公网 IP: ${data?.publicIp || "弹性公网 IP"}`,
      `本月账单查询结果: ${total}`,
      "",
      "【每日账单查询结果（可能延迟）】",
      lines.length > 0 ? lines.join("\n") : "暂无每日明细数据",
      "",
      data?.financialBillStatus === "unavailable"
        ? "账单接口暂不可用，请检查 BSS 权限或稍后刷新。"
        : "月内账单数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({
        title: "🌐 弹性 IP 每日费用明细",
        message: msg
      })
    }
  }

  const loadData = useCallback(
    async (cfg: AppConfig = config) => {
      if (!isConfigReady(cfg)) {
        setShowSettings(true)
        return
      }
      setLoading(true)
      setErrorMessage(null)
      try {
        appendLog("正在连接阿里云 OpenAPI...")
        const res = await fetchConsoleData(cfg)
        setData(res)
        const now = new Date()
        setLastUpdated(now)
        try {
          if (typeof Storage !== "undefined" && Storage?.set) {
            Storage.set(SNAPSHOT_STORAGE_KEY, JSON.stringify(res))
          }
        } catch {}
        appendLog(`CDT流量: ${res.totalGB} GB (${res.percentage}%)`)
        appendLog(`ECS 实例: ${res.ecsStatus} ${res.publicIp ? `(${res.publicIp})` : ""}`)
        if (res.financialBalance) {
          appendLog(`账户余额: ¥${res.financialBalance.availableCashAmount}`)
        }
      } catch (err: any) {
        const msg = humanizeAliyunError(err?.message || "网络请求失败，请检查配置")
        setErrorMessage(msg)
        appendLog(`错误: ${msg}`)
      } finally {
        setLoading(false)
      }
    },
    [config]
  )

  useEffect(() => {
    if (isConfigReady(config)) {
      loadData(config)
    }
  }, [])

  // 1. 如果正在打开设置页
  if (showSettings) {
    return (
      <NavigationStack>
        <SettingsView
          currentConfig={config}
          onSave={newCfg => {
            setConfig(newCfg)
            setShowSettings(false)
            loadData(newCfg)
          }}
          onCancel={() => setShowSettings(false)}
        />
      </NavigationStack>
    )
  }

  const isStarting = data?.ecsStatus === "Starting"
  const isStopping = data?.ecsStatus === "Stopping"
  const isTransitional = isStarting || isStopping
  const isRunning = data?.ecsStatus === "Running"
  const isStopped = data?.ecsStatus === "Stopped"

  const statusColor = isRunning
    ? "systemGreen"
    : isTransitional
      ? "systemOrange"
      : isStopped
        ? "systemIndigo"
        : errorMessage && !data
          ? "systemRed"
          : "secondaryLabel"

  const haloColor = isRunning
    ? "rgba(52, 199, 89, 0.28)"
    : isTransitional
      ? "rgba(255, 159, 10, 0.30)"
      : isStopped
        ? "rgba(88, 86, 214, 0.30)"
        : "rgba(142, 142, 147, 0.25)"

  const capsuleBg = isRunning
    ? "rgba(52, 199, 89, 0.10)"
    : isTransitional
      ? "rgba(255, 159, 10, 0.12)"
      : isStopped
        ? "rgba(88, 86, 214, 0.12)"
        : "rgba(142, 142, 147, 0.12)"

  const statusLabel = loading && !data
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
              : errorMessage
                ? "同步失败"
                : "等待同步"
  const publicIpLabel = loading
    ? "获取中..."
    : errorMessage && !data
      ? "获取失败，点击刷新"
      : data?.publicIp || (data ? "未绑定公网 IP" : "等待同步")
  const publicIpColor = data?.publicIp ? "systemBlue" : errorMessage && !data ? "systemRed" : "secondaryLabel"
  const visibleLogRows = Math.max(1, Math.min(logs.length, 5))
  const logCardHeight = logs.length === 0 ? 72 : Math.min(160, 24 + visibleLogRows * 28)
  const logViewportHeight = Math.max(48, logCardHeight - 24)

  const now = new Date()
  const currentDay = now.getDate()
  const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate()
  const monthTimeProgress = data?.monthTimeProgress ?? Math.min(100, Math.max(1, Number(((currentDay / lastDay) * 100).toFixed(1))))
  const cutoffReferenceGB =
    data?.vpsCutoffReferenceGB || config.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB
  const cutoffRemainingGB = data?.cutoffRemainingGB ?? Math.max(0, cutoffReferenceGB - (data?.totalGB || 0))
  const healthMeta = data
    ? getTrafficHealthMeta(data.totalGB, cutoffReferenceGB, data.percentage, monthTimeProgress)
    : null

  // 2. 主控制台展示 (Apple iOS 26 Liquid Glass Architecture)
  return (
    <NavigationStack>
      <ScrollView
        background="systemGray6"
        showsIndicators={false}
        safeAreaPadding={{ bottom: true }}
      >
        <VStack
          alignment="leading"
          spacing={14}
          padding={{ horizontal: 16, top: 12, bottom: 20 }}
        >
          {/* 顶部标题与设置/刷新入口 */}
          <HStack alignment="center" padding={{ horizontal: 4, bottom: 2 }}>
            <HStack spacing={8} alignment="center">
              <ZStack
                frame={{ width: 34, height: 34 }}
                background="rgba(0, 122, 255, 0.10)"
                clipShape={{ type: "capsule" }}
              >
                <Image systemName="cloud.fill" font={16} foregroundStyle="systemBlue" />
              </ZStack>
              <VStack alignment="leading" spacing={1}>
                <Text font="headline" bold foregroundStyle="label">
                  阿里云 CDT 监控
                </Text>
                <Text font={10} foregroundStyle="secondaryLabel">
                  {loading
                    ? "正在同步..."
                    : lastUpdated
                      ? `${String(lastUpdated.getHours()).padStart(2, "0")}:${String(lastUpdated.getMinutes()).padStart(2, "0")} 已同步`
                      : "等待同步"}
                </Text>
              </VStack>
            </HStack>
            <Spacer />
            <HStack spacing={8} alignment="center">
              {/* 全局刷新按钮 */}
              <Button
                action={() => loadData(config)}
                disabled={loading}
                buttonStyle="plain"
                accessibilityLabel="刷新数据"
              >
                <HStack
                  spacing={4}
                  padding={{ horizontal: 10, vertical: 6 }}
                  background="rgba(0, 122, 255, 0.10)"
                  border={{ style: "rgba(0, 122, 255, 0.25)", width: 0.75 }}
                  clipShape={{ type: "capsule" }}
                  alignment="center"
                  {...liquidGlass(true)}
                >
                  <Image systemName="arrow.clockwise" font={12} foregroundStyle="systemBlue" />
                  <Text font="caption1" bold foregroundStyle="systemBlue">
                    {loading ? "同步中" : "刷新"}
                  </Text>
                </HStack>
              </Button>
              {/* 设置入口 */}
              <Button
                action={() => setShowSettings(true)}
                buttonStyle="plain"
                accessibilityLabel="设置"
              >
                <HStack
                  spacing={4}
                  padding={{ horizontal: 10, vertical: 6 }}
                  background="rgba(0, 122, 255, 0.10)"
                  border={{ style: "rgba(0, 122, 255, 0.25)", width: 0.75 }}
                  clipShape={{ type: "capsule" }}
                  alignment="center"
                  {...liquidGlass(true)}
                >
                  <Image systemName="gearshape.fill" font={12} foregroundStyle="systemBlue" />
                  <Text font="caption1" bold foregroundStyle="systemBlue">设置</Text>
                </HStack>
              </Button>
            </HStack>
          </HStack>

          {errorMessage && (
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
                foregroundStyle="systemRed"
              />
              <Text
                font="caption1"
                bold
                foregroundStyle="systemRed"
                lineLimit={3}
                frame={{ maxWidth: Infinity, alignment: "leading" }}
              >
                {errorMessage}
              </Text>
            </HStack>
          )}

          {/* Section 1: ECS 实例状态 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
              实例运行状态
            </Text>
            <Spacer />
            <Text font={12} foregroundStyle="secondaryLabel">
              {config.regionId}
            </Text>
          </HStack>

          {/* 内容容器：纯白不透明（HIG 分层法则，卡片严禁玻璃叠玻璃） */}
          <VStack
            background="systemBackground"
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
                  foregroundStyle="systemGreen"
                />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundStyle="label">
                  ECS 云服务器
                </Text>
                <Text font="caption2" foregroundStyle="secondaryLabel" lineLimit={1}>
                  {config.ecsInstanceId}
                </Text>
              </VStack>
              {/* 运行状态胶囊 (双层呼吸微光雷达波纹发光圆点 + 动态语义色彩) */}
              <HStack
                padding={{ horizontal: 10, vertical: 5 }}
                background={capsuleBg}
                clipShape={{ type: "capsule" }}
                spacing={6}
                alignment="center"
              >
                <ZStack frame={{ width: 14, height: 14 }} alignment="center">
                  <Circle fill={haloColor} frame={{ width: 14, height: 14 }} />
                  <Circle fill={statusColor} frame={{ width: 7, height: 7 }} />
                </ZStack>
                <Text font={12} bold foregroundStyle={statusColor}>
                  {statusLabel}
                </Text>
              </HStack>
            </HStack>

            <Divider padding={{ leading: 64 }} />

            {/* IP与地域行 (支持点击一键复制与触感反馈) */}
            <Button
              action={handleCopyIp}
              buttonStyle="plain"
              accessibilityLabel="复制公网 IP 地址"
            >
              <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={12}>
                <ZStack
                  frame={{ width: 36, height: 36 }}
                  background="rgba(0, 122, 255, 0.10)"
                  clipShape={{ type: "rect", cornerRadius: 9, style: "continuous" }}
                >
                  <Image
                    systemName={isCopied ? "checkmark" : "network"}
                    font={16}
                    foregroundStyle={isCopied ? "systemGreen" : "systemBlue"}
                  />
                </ZStack>
                <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                  <Text font="subheadline" bold foregroundStyle="label">
                    公网 IP 地址
                  </Text>
                  <Text font="caption2" foregroundStyle={isCopied ? "systemGreen" : publicIpColor} lineLimit={1}>
                    {isCopied ? "已复制到剪贴板 ✓" : publicIpLabel}
                  </Text>
                </VStack>
                <HStack
                  spacing={4}
                  padding={{ horizontal: 8, vertical: 4 }}
                  background={isCopied ? "rgba(52, 199, 89, 0.12)" : "rgba(142, 142, 147, 0.10)"}
                  clipShape={{ type: "capsule" }}
                  alignment="center"
                >
                  <Image
                    systemName={isCopied ? "checkmark" : "doc.on.doc"}
                    font={11}
                    foregroundStyle={isCopied ? "systemGreen" : "secondaryLabel"}
                  />
                  <Text font={11} bold foregroundStyle={isCopied ? "systemGreen" : "secondaryLabel"}>
                    {isCopied ? "已复制" : "复制"}
                  </Text>
                </HStack>
              </HStack>
            </Button>

            <Divider padding={{ horizontal: 16 }} />

          </VStack>
          <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
            ECS 状态来自阿里云只读查询；开关机与熔断由 VPS 脚本独立负责。
          </Text>

          {/* Section 2: 账户资产与实时费用 (Apple Wallet HIG Card) */}
          {data && (
            <>
              <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
                <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
                  账户资产与费用
                </Text>
                <Spacer />
                <Button action={togglePrivacy} buttonStyle="plain" accessibilityLabel={isPrivacy ? "显示金额" : "隐藏金额"}>
                  <HStack spacing={4} alignment="center">
                    <Image
                      systemName={isPrivacy ? "eye.slash.fill" : "eye.fill"}
                      font={12}
                      foregroundStyle="secondaryLabel"
                    />
                    <Text font={11} foregroundStyle="secondaryLabel">
                      {isPrivacy ? "已隐藏" : "明细"}
                    </Text>
                  </HStack>
                </Button>
              </HStack>

              <VStack
                background="systemBackground"
                clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
                shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
                spacing={0}
                frame={{ maxWidth: Infinity, alignment: "leading" }}
              >
                <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center">
                  {/* 可用现金余额 */}
                  {data.financialBalance && (
                  <VStack alignment="leading" spacing={4} frame={{ maxWidth: Infinity }}>
                    <Text font={12} foregroundStyle="secondaryLabel">
                      账户现金余额
                    </Text>
                    <HStack alignment="lastTextBaseline" spacing={3}>
                      <Text font={14} bold foregroundStyle={data.financialBalance.status === "arrears" ? "systemRed" : "label"}>
                        {data.financialBalance.currency === "USD" ? "$" : "¥"}
                      </Text>
                      <Text font={22} bold foregroundStyle={data.financialBalance.status === "arrears" ? "systemRed" : "label"}>
                        {isPrivacy ? "****" : data.financialBalance.availableCashAmount}
                      </Text>
                    </HStack>
                    <HStack spacing={4} alignment="center">
                      <Circle
                        fill={
                          data.financialBalance.status === "sufficient"
                            ? "systemGreen"
                            : data.financialBalance.status === "low"
                              ? "systemOrange"
                              : "systemRed"
                        }
                        frame={{ width: 6, height: 6 }}
                      />
                      <Text
                        font={11}
                        foregroundStyle={
                          data.financialBalance.status === "sufficient"
                            ? "systemGreen"
                            : data.financialBalance.status === "low"
                              ? "systemOrange"
                              : "systemRed"
                        }
                      >
                        {data.financialBalance.status === "sufficient"
                          ? "资金充足"
                          : data.financialBalance.status === "low"
                            ? "余额偏低"
                            : "已欠费"}
                      </Text>
                    </HStack>
                  </VStack>
                  )}
                  {data.financialBalance && <Divider frame={{ height: 44 }} />}

                  {/* 当月账单查询结果 */}
                  <VStack alignment="leading" spacing={4} padding={{ leading: data.financialBalance ? 16 : 0 }} frame={{ maxWidth: Infinity }}>
                    <Text font={12} foregroundStyle="secondaryLabel">
                      本月账单查询金额
                    </Text>
                    <HStack alignment="lastTextBaseline" spacing={3}>
                      {data.financialBillStatus === "available" && (
                        <Text font={14} bold foregroundStyle="label">
                          {data.financialBill?.currency === "USD" ? "$" : "¥"}
                        </Text>
                      )}
                      <Text font={22} bold foregroundStyle="label">
                        {data.financialBillStatus === "unavailable"
                          ? "不可用"
                          : isPrivacy
                            ? "****"
                            : data.financialBill?.paymentAmount || "0.00"}
                      </Text>
                    </HStack>
                    <Text
                      font={11}
                      foregroundStyle={
                        data.financialBillStatus === "unavailable"
                          ? "systemOrange"
                          : data.financialBill && parseFloat(data.financialBill.paymentAmount) > 0
                            ? "systemOrange"
                            : "systemGreen"
                      }
                    >
                      {data.financialBillStatus === "unavailable"
                        ? "账单查询不可用"
                        : data.financialBill && parseFloat(data.financialBill.paymentAmount) > 0
                        ? "当前账单查询结果（可能延迟）"
                        : "当前查询未返回费用"}
                    </Text>
                  </VStack>
                </HStack>

                <Divider padding={{ horizontal: 16 }} />

                {/* ECS 实例与弹性 IP 分拆费用微晶卡片 (支持轻触弹窗查看每日明细) */}
                <HStack padding={{ horizontal: 14, vertical: 10 }} spacing={10}>
                  {/* ECS 实例费用微晶卡片 */}
                  <Button
                    action={handleShowEcsDaily}
                    buttonStyle="plain"
                    accessibilityLabel="查看 ECS 实例每日费用明细"
                    frame={{ maxWidth: Infinity }}
                  >
                    <HStack
                      padding={{ horizontal: 12, vertical: 8 }}
                      background="rgba(0, 122, 255, 0.06)"
                      border={{ style: "rgba(0, 122, 255, 0.18)", width: 0.75 }}
                      clipShape={{ type: "rect", cornerRadius: 12, style: "continuous" }}
                      frame={{ maxWidth: Infinity }}
                      alignment="center"
                      spacing={8}
                    >
                      <ZStack frame={{ width: 28, height: 28 }} background="rgba(0, 122, 255, 0.12)" clipShape={{ type: "capsule" }}>
                        <Image systemName="server.rack" font={12} foregroundStyle="systemBlue" />
                      </ZStack>
                      <VStack alignment="leading" spacing={1} frame={{ maxWidth: Infinity }}>
                        <HStack alignment="center" spacing={3}>
                          <Text font={11} foregroundStyle="secondaryLabel">实例费用</Text>
                          <Image systemName="chevron.right" font={8} foregroundStyle="tertiaryLabel" />
                        </HStack>
                        <Text font={14} bold foregroundStyle="label">
                          {data.financialBillStatus === "unavailable" ? "—" : isPrivacy ? "****" : `¥${data?.financialBill?.ecsAmount || "0.00"}`}
                        </Text>
                      </VStack>
                    </HStack>
                  </Button>

                  {/* 弹性 IP 费用微晶卡片 */}
                  <Button
                    action={handleShowEipDaily}
                    buttonStyle="plain"
                    accessibilityLabel="查看弹性 IP 每日费用明细"
                    frame={{ maxWidth: Infinity }}
                  >
                    <HStack
                      padding={{ horizontal: 12, vertical: 8 }}
                      background="rgba(88, 86, 214, 0.06)"
                      border={{ style: "rgba(88, 86, 214, 0.18)", width: 0.75 }}
                      clipShape={{ type: "rect", cornerRadius: 12, style: "continuous" }}
                      frame={{ maxWidth: Infinity }}
                      alignment="center"
                      spacing={8}
                    >
                      <ZStack frame={{ width: 28, height: 28 }} background="rgba(88, 86, 214, 0.12)" clipShape={{ type: "capsule" }}>
                        <Image systemName="globe.asia.australia" font={12} foregroundStyle="systemIndigo" />
                      </ZStack>
                      <VStack alignment="leading" spacing={1} frame={{ maxWidth: Infinity }}>
                        <HStack alignment="center" spacing={3}>
                          <Text font={11} foregroundStyle="secondaryLabel">弹性 IP</Text>
                          <Image systemName="chevron.right" font={8} foregroundStyle="tertiaryLabel" />
                        </HStack>
                        <Text font={14} bold foregroundStyle="label">
                          {data.financialBillStatus === "unavailable" ? "—" : isPrivacy ? "****" : `¥${data?.financialBill?.eipAmount || "0.00"}`}
                        </Text>
                      </VStack>
                    </HStack>
                  </Button>
                </HStack>
              </VStack>
              <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
                轻触实例费用或弹性 IP 卡片可查看最近每日消费明细与日均推算。
              </Text>
            </>
          )}

          {/* Section 2: CDT 流量用量卡片 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
              CDT 互联网出网流量
            </Text>
            <Spacer />
            {data && (
              <HStack
                padding={{ horizontal: 8, vertical: 3 }}
                background={data.totalGB >= cutoffReferenceGB
                  ? "rgba(255, 59, 48, 0.10)"
                  : data.totalGB >= cutoffReferenceGB - 15
                    ? "rgba(255, 149, 0, 0.10)"
                    : "rgba(52, 199, 89, 0.10)"}
                clipShape={{ type: "capsule" }}
              >
                <Text font={12} bold foregroundStyle={data.totalGB >= cutoffReferenceGB
                  ? "systemRed"
                  : data.totalGB >= cutoffReferenceGB - 15
                    ? "systemOrange"
                    : "systemGreen"}>
                  参考值进度 {data.percentage}%
                </Text>
              </HStack>
            )}
          </HStack>

          {/* 内容容器：纯白不透明 */}
          <VStack
            background="systemBackground"
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
                <Image systemName="arrow.up.and.down" font={16} foregroundStyle="systemPurple" />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundStyle="label">
                  出网用量 / 本地参考值
                </Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">
                  本地月用量参考值: {config.trafficThresholdGB} GB
                </Text>
              </VStack>
              {data && (
                <VStack alignment="trailing" spacing={2}>
                  <HStack alignment="lastTextBaseline" spacing={4}>
                    <Text font={28} bold foregroundStyle="label">
                      {data.totalGB.toFixed(2)}
                    </Text>
                    <Text font={14} bold foregroundStyle="label">
                      GB
                    </Text>
                  </HStack>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    / {data.thresholdGB} GB
                  </Text>
                </VStack>
              )}
            </HStack>

            {/* 线性进度条保持胶囊形状，浅色与深色都保留足够对比度 */}
            {data && (
              <VStack padding={{ horizontal: 16, top: 2, bottom: 12 }}>
                <ProgressView
                  progressViewStyle="linear"
                  value={Math.max(0.01, Math.min(1.0, data.percentage / 100))}
                  total={1}
                  tint={data.color as any}
                  frame={{ maxWidth: Infinity, height: 10 }}
                  clipShape={{ type: "capsule" }}
                />
              </VStack>
            )}

            {/* 时间进度 vs 流量进度健康度提示 */}
            {data && healthMeta && (
              <HStack
                spacing={6}
                alignment="center"
                padding={{ horizontal: 16, top: 0, bottom: 14 }}
              >
                <Image
                  systemName={healthMeta.icon}
                  font={12}
                  foregroundStyle={healthMeta.color}
                />
                <Text font={11} foregroundStyle={healthMeta.color} lineLimit={1}>
                  本月时间已过 {monthTimeProgress.toFixed(0)}% · 已用 {data.totalGB.toFixed(1)} GB · VPS {cutoffReferenceGB} GB 参考线余 {cutoffRemainingGB.toFixed(1)} GB（{healthMeta.label}）
                </Text>
              </HStack>
            )}

            <Divider padding={{ horizontal: 16 }} />

            {/* 三列指标卡片 (通透布局，去灰底，数值加粗大字号，内边距 16px) */}
            {data ? (
              <HStack padding={{ horizontal: 16, vertical: 16 }} alignment="center">
                {/* 本地月用量参考值余量或超出量 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    {data.totalGB > data.thresholdGB
                      ? "超出参考值"
                      : data.totalGB === data.thresholdGB
                        ? "已达到参考值"
                        : "参考值余量"}
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text
                      font={20}
                      bold
                      foregroundStyle={data.totalGB > data.thresholdGB ? "systemRed" : "systemBlue"}
                    >
                      {data.totalGB > data.thresholdGB
                        ? `+${(data.totalGB - data.thresholdGB).toFixed(1)}`
                        : data.remainingGB.toFixed(1)}
                    </Text>
                    <Text
                      font={12}
                      bold
                      foregroundStyle={data.totalGB > data.thresholdGB ? "systemRed" : "systemBlue"}
                    >
                      GB
                    </Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 28 }} />

                {/* 距结算重置 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    距结算重置
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundStyle="label">
                      {data.daysRemaining}
                    </Text>
                    <Text font={12} bold foregroundStyle="secondaryLabel">
                      天
                    </Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 28 }} />

                {/* 日均参考 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    日均参考
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundStyle={data.color}>
                      &lt; {data.dailyBudgetGB}
                    </Text>
                    <Text font={12} bold foregroundStyle={data.color}>
                      GB
                    </Text>
                  </HStack>
                </VStack>
              </HStack>
            ) : (
              <HStack padding={16} alignment="center">
                <Text font="caption2" foregroundStyle="secondaryLabel">
                  正在同步阿里云最新用量数据...
                </Text>
              </HStack>
            )}
          </VStack>
          <HStack alignment="top" spacing={8} padding={{ leading: 8, bottom: 4 }}>
            <Image systemName="antenna.radiowaves.left.and.right" font={12} foregroundStyle="systemBlue" />
            <Text
              font={12}
              foregroundStyle="secondaryLabel"
              lineLimit={3}
              frame={{ maxWidth: Infinity, alignment: "leading" }}
            >
              VPS 独立负责实例保活与熔断，手机只读展示。流量余量和进度按本地月用量参考值计算，不代表阿里云账号维度的完整免费额度余额。
            </Text>
          </HStack>

          {/* Section 3: 控制台实时操作日志 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
              实时操作日志
            </Text>
            <Spacer />
            <Button
              action={() => setLogs([])}
              disabled={logs.length === 0}
              buttonStyle="plain"
              accessibilityLabel="清空日志"
            >
              <HStack
                spacing={4}
                padding={{ horizontal: 10, vertical: 5 }}
                background="rgba(142, 142, 147, 0.12)"
                border={{ style: "rgba(142, 142, 147, 0.20)", width: 0.75 }}
                clipShape={{ type: "capsule" }}
                alignment="center"
                {...liquidGlass(true)}
              >
                <Image systemName="trash" font={11} foregroundStyle="secondaryLabel" />
                <Text font={11} bold foregroundStyle="secondaryLabel">
                  清空
                </Text>
              </HStack>
            </Button>
          </HStack>

          {/* 日志容器：少量内容收缩，超过五行才使用固定视口滚动 */}
          <VStack
            background="systemBackground"
            clipShape={{ type: "rect", cornerRadius: 20, style: "continuous" }}
            shadow={{ color: "rgba(0, 0, 0, 0.04)", radius: 12, x: 0, y: 3 }}
            spacing={0}
            padding={{ horizontal: 16, vertical: 12 }}
            frame={{ maxWidth: Infinity, height: logCardHeight, alignment: "leading" }}
          >
            <ScrollView showsIndicators={false} frame={{ maxWidth: Infinity, height: logViewportHeight }}>
              <VStack alignment="leading" spacing={7} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                {logs.length > 0 ? (
                  logs.map((log, index) => {
                    const parts = splitLogLine(log)
                    return (
                      <HStack key={index} spacing={6} alignment="top" frame={{ maxWidth: Infinity, alignment: "leading" }}>
                        <Text font={11} foregroundStyle="tertiaryLabel">•</Text>
                        <Text font={11} foregroundStyle="tertiaryLabel">
                          {parts.time}
                        </Text>
                        <Text
                          font={12}
                          foregroundStyle={logMessageColor(log)}
                          lineLimit={2}
                          frame={{ maxWidth: Infinity, alignment: "leading" }}
                        >
                          {parts.message}
                        </Text>
                      </HStack>
                    )
                  })
                ) : (
                  <Text font={12} foregroundStyle="secondaryLabel">
                    暂无日志，点击刷新同步。
                  </Text>
                )}
              </VStack>
            </ScrollView>
          </VStack>
          <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 8 }}>
            最近 8 条操作记录
          </Text>

          {/* 版本与构建信息 */}
          <VStack alignment="center" spacing={2} padding={{ top: 8, bottom: 20 }}>
            <Text font={11} foregroundStyle="quaternaryLabel">
              Aliyun CDT Monitor v{APP_VERSION}
            </Text>
          </VStack>
        </VStack>
      </ScrollView>
    </NavigationStack>
  )
}

// ==================== 7. 主执行入口 ====================

async function main() {
  await Navigation.present({
    element: <ConsoleView />
  })
  Script.exit()
}

main()
