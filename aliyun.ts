/**
 * 阿里云 POP OpenAPI 纯 TypeScript 客户端（内置 HMAC-SHA1 签名与 Base64）
 * 专为 iOS Scripting 环境设计，无需安装任何 npm 包或外部 SDK
 */
import { AppConfig, DEFAULT_CONFIG } from "./config"

// ==================== 1. 纯 TS HMAC-SHA1 算法实现 ====================

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

/** 计算 HMAC-SHA1 并输出 Base64 字符串 */
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

// ==================== 2. 阿里云 POP 签名与请求构造 ====================

/** 阿里云 RFC 3986 规范编码 */
function percentEncode(str: string): string {
  return encodeURIComponent(str)
    .replace(/!/g, "%21")
    .replace(/'/g, "%27")
    .replace(/\(/g, "%28")
    .replace(/\)/g, "%29")
    .replace(/\*/g, "%2A")
}

export interface RequestOptions {
  domain: string
  action: string
  version: string
  method?: "GET" | "POST"
  params?: Record<string, string | number | boolean>
}

/**
 * 发起经 POP 协议签名的阿里云 API 请求
 */
export async function aliyunRequest<T = any>(
  options: RequestOptions,
  config: AppConfig = DEFAULT_CONFIG
): Promise<T> {
  const method = options.method || "POST"
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z")
  const nonce = Date.now().toString(36) + Math.random().toString(36).substring(2)

  // 1. 组织公共与业务参数
  const allParams: Record<string, string> = {
    Format: "JSON",
    Version: options.version,
    AccessKeyId: config.accessKeyId,
    SignatureMethod: "HMAC-SHA1",
    Timestamp: timestamp,
    SignatureVersion: "1.0",
    SignatureNonce: nonce,
    Action: options.action,
    ...Object.fromEntries(
      Object.entries(options.params || {}).map(([k, v]) => [k, String(v)])
    )
  }

  // 2. 规范化参数排序与编码
  const sortedKeys = Object.keys(allParams).sort()
  const canonicalizedQueryString = sortedKeys
    .map(k => `${percentEncode(k)}=${percentEncode(allParams[k])}`)
    .join("&")

  // 3. 构造 StringToSign
  const stringToSign = `${method}&${percentEncode("/")}&${percentEncode(canonicalizedQueryString)}`

  // 4. 计算签名
  const signature = hmacSha1Base64(config.accessKeySecret + "&", stringToSign)

  // 5. 拼接最终请求
  const requestUrl = `https://${options.domain}/`
  const bodyString = `${canonicalizedQueryString}&Signature=${percentEncode(signature)}`

  let response: Response
  if (method === "GET") {
    response = await fetch(`${requestUrl}?${bodyString}`)
  } else {
    response = await fetch(requestUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: bodyString
    })
  }

  if (!response.ok) {
    const errorText = await response.text()
    throw new Error(`Aliyun API [${options.action}] Error (${response.status}): ${errorText}`)
  }

  return (await response.json()) as T
}

// ==================== 3. 业务数据模型与核心 API ====================

export interface CDTTrafficResult {
  totalBytes: number
  totalGB: number
  thresholdGB: number
  remainingGB: number
  percentage: number
  statusLevel: "normal" | "warning" | "danger"
  updatedAt: Date
}

export type ECSStatus = "Running" | "Stopped" | "Starting" | "Stopping" | "Unknown"

export interface ECSInstanceInfo {
  instanceId: string
  status: ECSStatus
  publicIp?: string
  instanceName?: string
}

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

type ECSIpValue = string | string[] | undefined

interface ECSInstanceRecord {
  InstanceId: string
  Status: string
  InstanceName?: string
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

export class AliyunService {
  private config: AppConfig

  constructor(config: AppConfig = DEFAULT_CONFIG) {
    this.config = config
  }

  /**
   * 1. 获取 CDT 本月总互联网出网流量 (GB)
   */
  async getCDTTraffic(): Promise<CDTTrafficResult> {
    const data = await aliyunRequest<{
      TrafficDetails?: Array<{ Traffic?: number; Product?: string }>
    }>(
      {
        domain: "cdt.aliyuncs.com",
        action: "ListCdtInternetTraffic",
        version: "2021-08-13",
        method: "POST"
      },
      this.config
    )

    const details = data.TrafficDetails || []
    const totalBytes = details.reduce((sum, item) => sum + (item.Traffic || 0), 0)
    const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
    const thresholdGB = this.config.trafficThresholdGB
    const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
    const percentage = Math.min(100, Number(((totalGB / thresholdGB) * 100).toFixed(1)))

    let statusLevel: "normal" | "warning" | "danger" = "normal"
    if (percentage >= 90 || totalGB >= thresholdGB) {
      statusLevel = "danger"
    } else if (percentage >= 70) {
      statusLevel = "warning"
    }

    return {
      totalBytes,
      totalGB,
      thresholdGB,
      remainingGB,
      percentage,
      statusLevel,
      updatedAt: new Date()
    }
  }

  /**
   * 2. 获取 ECS 实例运行状态
   */
  async getECSStatus(instanceId: string = this.config.ecsInstanceId): Promise<ECSInstanceInfo> {
    const domain = `ecs.${this.config.regionId}.aliyuncs.com`
    const data = await aliyunRequest<{
      Instances?: {
        Instance?: ECSInstanceRecord[]
      }
    }>(
      {
        domain,
        action: "DescribeInstances",
        version: "2014-05-26",
        method: "POST",
        params: {
          InstanceIds: JSON.stringify([instanceId]),
          RegionId: this.config.regionId
        }
      },
      this.config
    )

    const instance = data.Instances?.Instance?.[0]
    if (!instance) {
      return {
        instanceId,
        status: "Unknown"
      }
    }

    return {
      instanceId: instance.InstanceId,
      status: (instance.Status as ECSStatus) || "Unknown",
      publicIp: getInstancePublicIp(instance),
      instanceName: instance.InstanceName
    }
  }

  /**
   * 3. 启动 ECS 实例
   */
  async startECS(instanceId: string = this.config.ecsInstanceId): Promise<boolean> {
    const current = await this.getECSStatus(instanceId)
    if (current.status === "Running") {
      return true
    }
    const domain = `ecs.${this.config.regionId}.aliyuncs.com`
    await aliyunRequest(
      {
        domain,
        action: "StartInstance",
        version: "2014-05-26",
        method: "POST",
        params: {
          InstanceId: instanceId
        }
      },
      this.config
    )
    return true
  }

  /**
   * 4. 停止 ECS 实例 (默认软关机)
   */
  async stopECS(instanceId: string = this.config.ecsInstanceId, forceStop: boolean = false): Promise<boolean> {
    const current = await this.getECSStatus(instanceId)
    if (current.status === "Stopped") {
      return true
    }
    const domain = `ecs.${this.config.regionId}.aliyuncs.com`
    await aliyunRequest(
      {
        domain,
        action: "StopInstance",
        version: "2014-05-26",
        method: "POST",
        params: {
          InstanceId: instanceId,
          ForceStop: forceStop
        }
      },
      this.config
    )
    return true
  }

  /**
   * 5. 执行熔断检查：超额自动关机保护
   */
  async checkAndEnforceThreshold(): Promise<{
    triggered: boolean
    traffic: CDTTrafficResult
    ecs: ECSInstanceInfo
  }> {
    const traffic = await this.getCDTTraffic()
    const ecs = await this.getECSStatus()

    let triggered = false
    if (this.config.autoStopOnExceed && traffic.totalGB >= this.config.trafficThresholdGB) {
      if (ecs.status === "Running" || ecs.status === "Starting") {
        await this.stopECS()
        triggered = true
        ecs.status = "Stopping"
      }
    }

    return { triggered, traffic, ecs }
  }

  /**
   * 6. 重启 ECS 实例
   */
  async rebootECS(instanceId: string = this.config.ecsInstanceId, forceStop: boolean = false): Promise<boolean> {
    const domain = `ecs.${this.config.regionId}.aliyuncs.com`
    await aliyunRequest(
      {
        domain,
        action: "RebootInstance",
        version: "2014-05-26",
        method: "POST",
        params: {
          InstanceId: instanceId,
          ForceStop: forceStop
        }
      },
      this.config
    )
    return true
  }

  /**
   * 7. 获取账户可用余额 (支持优雅降级，未授权返回 null)
   */
  async getAccountBalance(): Promise<AccountBalanceInfo | null> {
    try {
      const data = await aliyunRequest<{
        Data?: {
          AvailableAmount?: string
          AvailableCashAmount?: string
          CreditAmount?: string
          Currency?: string
        }
      }>(
        {
          domain: "business.aliyuncs.com",
          action: "QueryAccountBalance",
          version: "2017-12-14",
          method: "POST"
        },
        this.config
      )
      if (!data?.Data) return null
      const cash = parseFloat(data.Data.AvailableCashAmount || "0")
      let status: "sufficient" | "low" | "arrears" = "sufficient"
      if (cash <= 0) {
        status = "arrears"
      } else if (cash < 10) {
        status = "low"
      }
      return {
        availableAmount: data.Data.AvailableAmount || "0.00",
        availableCashAmount: data.Data.AvailableCashAmount || "0.00",
        currency: data.Data.Currency || "CNY",
        status
      }
    } catch {
      return null
    }
  }

  /**
   * 8. 获取当月实时累计消费账单 (支持优雅降级，未授权返回 null)
   */
  async getMonthlyBill(): Promise<MonthlyBillInfo | null> {
    try {
      const now = new Date()
      const currentDay = now.getDate()
      const cycle = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`

      // 1. 优先调用 QueryBillOverview（官方控制台账单总览对齐，按产品维度直接汇总，确保 ECS/EIP 精确识别）
      let items: Array<{
        PipCode?: string
        ProductCode?: string
        ProductName?: string
        PaymentAmount?: number
        PretaxGrossAmount?: number
        PretaxAmount?: number
        OutstandingAmount?: number
        Currency?: string
      }> = []

      try {
        const overviewData = await aliyunRequest<{
          Data?: {
            Items?: {
              Item?: Array<any>
            }
          }
        }>(
          {
            domain: "business.aliyuncs.com",
            action: "QueryBillOverview",
            version: "2017-12-14",
            method: "POST",
            params: {
              BillingCycle: cycle
            }
          },
          this.config
        )
        if (overviewData?.Data?.Items?.Item && overviewData.Data.Items.Item.length > 0) {
          items = overviewData.Data.Items.Item
        }
      } catch {}

      // 2. 若 QueryBillOverview 无数据，回退至 QueryAccountBill（必须携带 IsGroupByProduct: true 才能返回产品层级分类）
      if (items.length === 0) {
        try {
          const accountBillData = await aliyunRequest<{
            Data?: {
              Items?: {
                Item?: Array<any>
              }
            }
          }>(
            {
              domain: "business.aliyuncs.com",
              action: "QueryAccountBill",
              version: "2017-12-14",
              method: "POST",
              params: {
                BillingCycle: cycle,
                IsGroupByProduct: true
              }
            },
            this.config
          )
          if (accountBillData?.Data?.Items?.Item && accountBillData.Data.Items.Item.length > 0) {
            items = accountBillData.Data.Items.Item
          }
        } catch {}
      }

      if (items.length === 0) {
        return null
      }

      let totalPayment = 0
      let totalGross = 0
      let allProductsEffective = 0
      let ecsTotal = 0
      let eipTotal = 0
      let cdtTotal = 0
      let outstanding = 0
      let currency = "CNY"

      for (const it of items) {
        const code = String(it.PipCode || it.ProductCode || "").toLowerCase()
        const name = String(it.ProductName || "")
        const pay = Number(it.PaymentAmount || 0)
        const gross = Number(it.PretaxGrossAmount || 0)
        // 关键：必须优先取 PretaxAmount（实际应付金额：已扣除抢占式竞价折扣、优惠券，如抢占式实例单日仅 0.13 元而非原价 0.94 元）
        let effective = 0
        if (it.PretaxAmount !== undefined && it.PretaxAmount !== null && it.PretaxAmount !== "") {
          effective = Number(it.PretaxAmount) || 0
        } else if (pay > 0) {
          effective = pay
        } else {
          effective = gross
        }

        totalPayment += pay
        totalGross += gross
        allProductsEffective += effective
        outstanding += Number(it.OutstandingAmount || 0)
        if (it.Currency) currency = it.Currency

        // 强壮的云服务分类模糊识别
        const isEcs = code === "ecs" || code.includes("ecs") || name.includes("云服务器") || name.includes("ECS")
        const isEip = code === "eip" || code === "cbwp" || code.includes("eip") || code.includes("cbwp") || name.includes("弹性公网") || name.includes("EIP") || name.includes("公网IP") || name.includes("共享带宽")
        const isCdt = code === "cdt" || code.includes("cdt") || name.includes("云数据传输") || name.includes("CDT")

        if (isEcs) {
          ecsTotal += effective
        } else if (isEip) {
          eipTotal += effective
        } else if (isCdt) {
          cdtTotal += effective
        }
      }

      // 当月消费严格对齐阿里云控制台账单中心：优先采用各项产品实际累计（如 ECS ¥0.40 + EIP ¥0.04 = ¥0.44）
      const infrastructureTotal = ecsTotal + eipTotal + cdtTotal
      const finalPayment = infrastructureTotal > 0
        ? infrastructureTotal
        : (allProductsEffective > 0 ? allProductsEffective : (totalPayment > 0 ? totalPayment : totalGross))

      const formatDaily = (amt: number): string => {
        if (amt <= 0) return "0.00"
        if (amt < 0.01) return amt.toFixed(3)
        return amt.toFixed(2)
      }

      // 真实读取最近各日期的官方实际账单（QueryAccountBill + DAILY，真实 API 读取，绝非推算）
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
              }>(
                {
                  domain: "business.aliyuncs.com",
                  action: "QueryAccountBill",
                  version: "2017-12-14",
                  method: "POST",
                  params: {
                    BillingCycle: cycle,
                    Granularity: "DAILY",
                    BillingDate: q.dateStr,
                    IsGroupByProduct: true
                  }
                },
                this.config
              )
              const dayItems = dayRes?.Data?.Items?.Item || []
              let dEcs = 0
              let dEip = 0
              for (const it of dayItems) {
                const c = String(it.PipCode || it.ProductCode || "").toLowerCase()
                const n = String(it.ProductName || "")
                const p = Number(it.PaymentAmount || 0)
                const g = Number(it.PretaxGrossAmount || 0)
                // 优先取 PretaxAmount（抢占式实例折扣后的真实应付金额）
                let eff = 0
                if (it.PretaxAmount !== undefined && it.PretaxAmount !== null && it.PretaxAmount !== "") {
                  eff = Number(it.PretaxAmount) || 0
                } else if (p > 0) {
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
                settled: dayItems.length > 0
              }
            } catch {
              return {
                date: q.displayDate,
                isToday: q.isToday,
                ecsAmount: "0.00",
                eipAmount: "0.00",
                settled: false
              }
            }
          })
        )

        for (const r of dailyResults) {
          ecsDailyList.push({ date: r.date, amount: r.ecsAmount, isToday: r.isToday, settled: r.settled })
          eipDailyList.push({ date: r.date, amount: r.eipAmount, isToday: r.isToday, settled: r.settled })
        }
      } catch {
        for (const q of dateQueries) {
          ecsDailyList.push({ date: q.displayDate, amount: "0.00", isToday: q.isToday, settled: false })
          eipDailyList.push({ date: q.displayDate, amount: "0.00", isToday: q.isToday, settled: false })
        }
      }

      return {
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
    } catch {
      return null
    }
  }
}
