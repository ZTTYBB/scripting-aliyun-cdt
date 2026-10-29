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
  List,
  Section,
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
  useState,
  useEffect,
  useCallback
} from "scripting"
import {
  aliyunHttpError,
  assertSampleBillingMonth,
  chinaMonthKey,
  chinaMonthProgress,
  createRefreshGate,
  createSnapshot,
  normalizeEcsStatus,
  readSnapshot,
  recordTrafficSample,
  usagePercentage,
  withRequestTimeout,
  accountDisplayName,
  bssEndpoint,
  loadAccountProfiles,
  newAccountId,
  removeAccountProfile,
  saveAccountProfiles,
  scopedStorageKey,
  siteLabel,
  upsertAccountProfile
} from "./monitor_runtime"
import { isBillQueryAvailable, queryAccountBillPages, recentBillingDates } from "./bill_queries"

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

interface MonthlyBillHistoryItem {
  billingCycle: string
  paymentAmount: string
  currency: string
  available: boolean
  hasRecords?: boolean
  paymentScope?: "monitoredProducts" | "allProducts"
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

function currencySymbol(currency?: string): string {
  if (currency === "USD") return "$"
  if (currency === "CNY" || !currency) return "¥"
  return `${currency} `
}

async function queryBillItemsForCycle(
  config: AppConfig,
  billingCycle: string
): Promise<{ available: boolean; items: Array<any> }> {
  const overviewRes = await aliyunRequest<{
    Data?: {
      Items?: {
        Item?: Array<any>
      }
    }
    Success?: boolean
    Code?: string
  }>(bssEndpoint(config), "QueryBillOverview", "2017-12-14", config, {
    BillingCycle: billingCycle
  }).catch(() => null)

  if (isBillQueryAvailable(overviewRes) && overviewRes!.Data!.Items!.Item!.length > 0) {
    return { available: true, items: overviewRes!.Data!.Items!.Item! }
  }

  return queryAccountBillPages(
    params => aliyunRequest(bssEndpoint(config), "QueryAccountBill", "2017-12-14", config, params),
    { BillingCycle: billingCycle, IsGroupByProduct: true }
  )
}

interface BillSummary {
  paymentAmount: number
  outstandingAmount: number
  currency: string
  ecsAmount: number
  eipAmount: number
  cdtAmount: number
  paymentScope: "monitoredProducts" | "allProducts"
}

function summarizeBillItems(items: Array<any>, includeAllProducts = false): BillSummary {
  let allProductsEffective = 0
  let ecsTotal = 0
  let eipTotal = 0
  let cdtTotal = 0
  let hasInfrastructureItems = false
  let outstanding = 0
  let currency = "CNY"

  for (const item of items) {
    const code = String(item?.PipCode || item?.ProductCode || "").toLowerCase()
    const name = String(item?.ProductName || "")
    const gross = Number(item?.PretaxGrossAmount || 0)
    const effective =
      item?.PretaxAmount !== undefined && item?.PretaxAmount !== null && item?.PretaxAmount !== ""
        ? Number(item.PretaxAmount) || 0
        : item?.PaymentAmount !== undefined && item?.PaymentAmount !== null && item?.PaymentAmount !== ""
          ? Number(item.PaymentAmount) || 0
          : gross

    allProductsEffective += effective
    outstanding += Number(item?.OutstandingAmount || 0)
    if (item?.Currency) currency = String(item.Currency)

    const isEcs = code === "ecs" || code.includes("ecs") || name.includes("云服务器") || name.includes("ECS")
    const isEip =
      code === "eip" ||
      code === "cbwp" ||
      code.includes("eip") ||
      code.includes("cbwp") ||
      name.includes("弹性公网") ||
      name.includes("EIP") ||
      name.includes("公网IP") ||
      name.includes("共享带宽")
    const isCdt = code === "cdt" || code.includes("cdt") || name.includes("云数据传输") || name.includes("CDT")

    if (isEcs || isEip || isCdt) hasInfrastructureItems = true
    if (isEcs) ecsTotal += effective
    else if (isEip) eipTotal += effective
    else if (isCdt) cdtTotal += effective
  }

  return {
    paymentAmount: includeAllProducts || !hasInfrastructureItems
      ? allProductsEffective
      : ecsTotal + eipTotal + cdtTotal,
    outstandingAmount: outstanding,
    currency,
    ecsAmount: ecsTotal,
    eipAmount: eipTotal,
    cdtAmount: cdtTotal,
    paymentScope: includeAllProducts || !hasInfrastructureItems ? "allProducts" : "monitoredProducts"
  }
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
  isCached?: boolean
  financialBalance?: AccountBalanceInfo | null
  financialBill?: MonthlyBillInfo | null
  financialBillStatus: "available" | "unavailable"
  previousFinancialBill?: MonthlyBillInfo | null
  previousFinancialBillStatus: "available" | "unavailable"
  financialBillHistory: MonthlyBillHistoryItem[]
  trafficDiagnostics?: CDTTrafficDiagnostics
}

interface CDTTrafficDetail {
  Traffic?: number | string
  Product?: string
  BusinessRegionId?: string
  ISPType?: string
  ProductTrafficDetails?: unknown
  TrafficTierDetails?: unknown
}

type CDTTrafficBucket = "mainland" | "nonMainland" | "unknown"

interface CDTTrafficGroup {
  bucket: CDTTrafficBucket
  businessRegionId?: string
  ispType?: string
  totalBytes: number
  totalGB: number
  itemCount: number
}

interface CDTTrafficBucketSummary {
  bucket: CDTTrafficBucket
  totalBytes: number
  totalGB: number
  itemCount: number
}

interface CDTTrafficDiagnostics {
  buckets: Record<CDTTrafficBucket, CDTTrafficBucketSummary>
  groups: CDTTrafficGroup[]
}

function trafficBytes(value: unknown): number {
  const parsed = typeof value === "number" ? value : Number(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 0
}

function diagnosticField(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

// Keep this an explicit allowlist. A `cn-*` prefix is insufficient because
// `cn-hongkong` is non-mainland for CDT quota accounting.
const CDT_MAINLAND_BUSINESS_REGION_IDS = new Set([
  "cn-beijing",
  "cn-changsha",
  "cn-chengdu",
  "cn-dalian",
  "cn-fuzhou",
  "cn-guangzhou",
  "cn-hangzhou",
  "cn-heyuan",
  "cn-huhehaote",
  "cn-jinan",
  "cn-nanjing",
  "cn-qingdao",
  "cn-shanghai",
  "cn-shenzhen",
  "cn-wuhan",
  "cn-wulanchabu",
  "cn-xian",
  "cn-zhangjiakou",
  "cn-zhengzhou"
])
const CDT_NON_MAINLAND_BUSINESS_REGION_IDS = new Set(["cn-hongkong"])

function classifyCDTTrafficBucket(value: unknown): CDTTrafficBucket {
  const normalized = diagnosticField(value)?.toLowerCase()
  if (!normalized) return "unknown"
  if (CDT_MAINLAND_BUSINESS_REGION_IDS.has(normalized)) return "mainland"
  if (CDT_NON_MAINLAND_BUSINESS_REGION_IDS.has(normalized)) return "nonMainland"
  return "unknown"
}

function buildCDTTrafficDiagnostics(details: CDTTrafficDetail[]): CDTTrafficDiagnostics {
  const buckets: Record<CDTTrafficBucket, CDTTrafficBucketSummary> = {
    mainland: { bucket: "mainland", totalBytes: 0, totalGB: 0, itemCount: 0 },
    nonMainland: { bucket: "nonMainland", totalBytes: 0, totalGB: 0, itemCount: 0 },
    unknown: { bucket: "unknown", totalBytes: 0, totalGB: 0, itemCount: 0 }
  }
  const grouped = new Map<string, CDTTrafficGroup>()

  for (const detail of details) {
    const totalBytes = trafficBytes(detail?.Traffic)
    const businessRegionId = diagnosticField(detail?.BusinessRegionId)
    const ispType = diagnosticField(detail?.ISPType)
    const bucket = classifyCDTTrafficBucket(businessRegionId)
    const summary = buckets[bucket]
    summary.totalBytes += totalBytes
    summary.itemCount += 1
    const key = `${bucket}\u0000${businessRegionId || ""}\u0000${ispType || ""}`
    const existing = grouped.get(key)
    if (existing) {
      existing.totalBytes += totalBytes
      existing.itemCount += 1
    } else {
      grouped.set(key, { bucket, businessRegionId, ispType, totalBytes, totalGB: 0, itemCount: 1 })
    }
  }

  for (const summary of Object.values(buckets)) {
    summary.totalGB = Number((summary.totalBytes / 1024 ** 3).toFixed(2))
  }
  const groups = Array.from(grouped.values()).map(group => ({
    ...group,
    totalGB: Number((group.totalBytes / 1024 ** 3).toFixed(2))
  }))
  return { buckets, groups }
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
  const trafficSampledAt = new Date()
  // 1. 查询 CDT 流量（必须成功，其余查询都依赖它确认凭据可用）
  const cdtData = await aliyunRequest<{
    TrafficDetails?: CDTTrafficDetail[]
  }>("cdt.aliyuncs.com", "ListCdtInternetTraffic", "2021-08-13", config)
  assertSampleBillingMonth(trafficSampledAt)

  const details = cdtData.TrafficDetails || []
  const trafficDiagnostics = buildCDTTrafficDiagnostics(details)
  const totalBytes = details.reduce((sum, item) => sum + trafficBytes(item.Traffic), 0)
  const totalGB = Number((totalBytes / 1024 ** 3).toFixed(2))
  const thresholdGB = config.trafficThresholdGB > 0 ? config.trafficThresholdGB : DEFAULT_CONFIG.trafficThresholdGB
  const vpsCutoffReferenceGB = config.vpsCutoffReferenceGB > 0 ? config.vpsCutoffReferenceGB : DEFAULT_CONFIG.vpsCutoffReferenceGB
  const cutoffRemainingGB = Math.max(0, Number((vpsCutoffReferenceGB - totalGB).toFixed(2)))
  const remainingGB = Math.max(0, Number((thresholdGB - totalGB).toFixed(2)))
  const percentage = usagePercentage(totalGB, thresholdGB)

  // 2. 重置日与时间进度推算（按阿里云账期所用的北京时间）
  const now = trafficSampledAt
  const { daysRemaining, monthTimeProgress } = chinaMonthProgress(now)
  const dailyBudgetGB = (remainingGB / daysRemaining).toFixed(2)
  const cycle = chinaMonthKey(now)
  const previousCycle = chinaMonthKey(now, -1)

  // 3. 其余查询互不依赖，并行发出；任何一项失败都不影响流量展示。
  const ecsTask = aliyunRequest<{
    Instances?: {
      Instance?: ECSInstanceRecord[]
    }
  }>(`ecs.${config.regionId}.aliyuncs.com`, "DescribeInstances", "2014-05-26", config, {
    InstanceIds: JSON.stringify([config.ecsInstanceId.trim()]),
    RegionId: config.regionId.trim()
  }).catch(() => null)

  const balanceTask = aliyunRequest<{
    Data?: {
      AvailableAmount?: string
      AvailableCashAmount?: string
      CreditAmount?: string
      Currency?: string
    }
  }>(bssEndpoint(config), "QueryAccountBalance", "2017-12-14", config).catch(() => null)

  const cycleTask = (billingCycle: string) => queryBillItemsForCycle(config, billingCycle).catch(() => null)
  const currentTask = cycleTask(cycle)
  const previousTask = cycleTask(previousCycle)
  const olderCycles = [chinaMonthKey(now, -2), chinaMonthKey(now, -3)]
  const olderTasks = olderCycles.map(cycleTask)

  const formatDaily = (amt: number): string => {
    if (amt <= 0) return "0.00"
    if (amt < 0.01) return amt.toFixed(3)
    return amt.toFixed(2)
  }

  // 仅在账单总览或回退接口已确认可用后，才查询每日产品账单分类。
  const dailyTask = currentTask.then(async monthResult => {
    const dateQueries = recentBillingDates(now)
    if (!monthResult?.available) return null
    return Promise.all(dateQueries.map(async q => {
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
        const summary = summarizeBillItems(dayResult.items)
        return {
          date: q.displayDate,
          isToday: q.isToday,
          ecsAmount: formatDaily(summary.ecsAmount),
          eipAmount: formatDaily(summary.eipAmount),
          settled: dayResult.items.length > 0,
          available: dayResult.available
        }
      } catch {
        return { date: q.displayDate, isToday: q.isToday, ecsAmount: "0.00", eipAmount: "0.00", settled: false, available: false }
      }
    }))
  })

  const [ecsData, balRes, monthResult, previousResult, dailyResults, ...olderResults] = await Promise.all([
    ecsTask,
    balanceTask,
    currentTask,
    previousTask,
    dailyTask.catch(() => null),
    ...olderTasks
  ])

  const instance = ecsData?.Instances?.Instance?.[0]
  const ecsStatus: ConsoleData["ecsStatus"] = normalizeEcsStatus(instance?.Status)
  const publicIp = getInstancePublicIp(instance)

  let financialBalance: AccountBalanceInfo | null = null
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

  // 所有账期统一按同一口径（监控产品；未识别到监控产品时为全部产品）汇总，便于逐月对比。
  const financialBillStatus: "available" | "unavailable" = monthResult?.available ? "available" : "unavailable"
  let financialBill: MonthlyBillInfo | null = null
  if (monthResult?.available) {
    const currentSummary = summarizeBillItems(monthResult.items)
    const ecsDailyList: DailyExpenseItem[] = []
    const eipDailyList: DailyExpenseItem[] = []
    const rows = dailyResults || recentBillingDates(now).map(q => ({
      date: q.displayDate, isToday: q.isToday, ecsAmount: "0.00", eipAmount: "0.00", settled: false, available: false
    }))
    for (const r of rows) {
      ecsDailyList.push({ date: r.date, amount: r.ecsAmount, isToday: r.isToday, settled: r.settled, available: r.available })
      eipDailyList.push({ date: r.date, amount: r.eipAmount, isToday: r.isToday, settled: r.settled, available: r.available })
    }
    financialBill = {
      billingCycle: cycle,
      paymentAmount: currentSummary.paymentAmount.toFixed(2),
      hasRecords: monthResult.items.length > 0,
      paymentScope: currentSummary.paymentScope,
      outstandingAmount: currentSummary.outstandingAmount.toFixed(2),
      currency: currentSummary.currency,
      ecsAmount: currentSummary.ecsAmount.toFixed(2),
      eipAmount: currentSummary.eipAmount.toFixed(2),
      cdtAmount: currentSummary.cdtAmount.toFixed(2),
      ecsDailyList,
      eipDailyList
    }
  }

  // 账期已结束的上月金额单独查询。余额接口不会返回扣费历史，不能用余额变化代替账单。
  const previousFinancialBillStatus: "available" | "unavailable" = previousResult?.available ? "available" : "unavailable"
  let previousFinancialBill: MonthlyBillInfo | null = null
  if (previousResult?.available && previousResult.items.length > 0) {
    const summary = summarizeBillItems(previousResult.items)
    previousFinancialBill = {
      billingCycle: previousCycle,
      paymentAmount: summary.paymentAmount.toFixed(2),
      paymentScope: summary.paymentScope,
      outstandingAmount: summary.outstandingAmount.toFixed(2),
      currency: summary.currency,
      ecsAmount: summary.ecsAmount.toFixed(2),
      eipAmount: summary.eipAmount.toFixed(2),
      cdtAmount: summary.cdtAmount.toFixed(2),
      ecsDailyList: [],
      eipDailyList: []
    }
  }

  const financialBillHistory: MonthlyBillHistoryItem[] = [
    {
      billingCycle: cycle,
      paymentAmount: financialBill?.paymentAmount || "0.00",
      currency: financialBill?.currency || financialBalance?.currency || "CNY",
      available: financialBillStatus === "available",
      hasRecords: Boolean(financialBill) && financialBill?.hasRecords !== false,
      paymentScope: financialBill?.paymentScope
    },
    {
      billingCycle: previousCycle,
      paymentAmount: previousFinancialBill?.paymentAmount || "0.00",
      currency: previousFinancialBill?.currency || financialBalance?.currency || "CNY",
      available: previousFinancialBillStatus === "available",
      hasRecords: Boolean(previousFinancialBill),
      paymentScope: previousFinancialBill?.paymentScope
    },
    ...olderCycles.map((billingCycle, index) => {
      const result = olderResults[index]
      const summary = result && result.items.length > 0 ? summarizeBillItems(result.items) : null
      return {
        billingCycle,
        paymentAmount: summary ? summary.paymentAmount.toFixed(2) : "0.00",
        currency: summary?.currency || financialBalance?.currency || "CNY",
        available: Boolean(result?.available),
        hasRecords: Boolean(result && result.items.length > 0),
        paymentScope: summary?.paymentScope
      }
    })
  ]

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
    financialBillStatus,
    previousFinancialBill,
    previousFinancialBillStatus,
    financialBillHistory,
    trafficDiagnostics
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

function formatCompactUsage(value: number): string {
  if (!Number.isFinite(value)) return "—"
  const absoluteValue = Math.abs(value)
  if (absoluteValue >= 100000000) {
    return `${(value / 100000000).toFixed(1)}亿`
  }
  if (absoluteValue >= 10000) {
    return `${(value / 10000).toFixed(1)}万`
  }
  if (absoluteValue >= 1000) {
    return value.toFixed(0)
  }
  return value.toFixed(1)
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

function splitLogLine(log: string): { time: string; message: string } {
  const match = log.match(/^(\[[^\]]+\])\s*(.*)$/)
  return match ? { time: match[1], message: match[2] } : { time: "", message: log }
}

function logMessageColor(log: string): string {
  if (/错误|失败/.test(log)) return "systemRed"
  if (/成功|完成|已发送/.test(log)) return "systemGreen"
  return "label"
}

// ==================== 4. 原生分组卡片样式 ====================

// Native inset-grouped card: solid white (light) / elevated gray (dark), like Settings.
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

function MonthlyTrafficOverview({
  data,
  thresholdGB,
  lastUpdated,
  loading
}: {
  data: ConsoleData | null
  thresholdGB: number
  lastUpdated: Date | null
  loading: boolean
}) {
  const mainland = data?.trafficDiagnostics?.buckets.mainland
  const nonMainland = data?.trafficDiagnostics?.buckets.nonMainland
  const unknown = data?.trafficDiagnostics?.buckets.unknown
  const updated = lastUpdated
    ? `${String(lastUpdated.getHours()).padStart(2, "0")}:${String(lastUpdated.getMinutes()).padStart(2, "0")}`
    : null

  return (
    <VStack alignment="leading" spacing={12} frame={{ maxWidth: Infinity }}>
      <HStack alignment="center">
        <Text font="subheadline" fontWeight="semibold" foregroundStyle="label">本月出网流量</Text>
        <Spacer />
        <Text font="footnote" monospacedDigit foregroundStyle="secondaryLabel">
          {loading ? "正在更新…" : updated ? `${data?.isCached ? "缓存 · " : ""}${updated} 更新` : "等待同步"}
        </Text>
      </HStack>
      <HStack alignment="lastTextBaseline" spacing={4}>
        <Text font={44} fontWeight="bold" monospacedDigit foregroundStyle="label" lineLimit={1} minScaleFactor={0.6}>
          {data ? data.totalGB.toFixed(2) : "--"}
        </Text>
        <Text font="title3" fontWeight="semibold" foregroundStyle="secondaryLabel">GB</Text>
        <Spacer />
        <Text font="subheadline" monospacedDigit foregroundStyle="secondaryLabel">/ {thresholdGB} GB</Text>
      </HStack>
      <ProgressView
        progressViewStyle="linear"
        value={data ? Math.min(1, Math.max(0, data.percentage / 100)) : 0}
        total={1}
        tint={data && data.totalGB >= thresholdGB ? "systemOrange" : "systemBlue"}
        frame={{ maxWidth: Infinity }}
      />
      <Divider />
      <HStack alignment="top" spacing={0} frame={{ maxWidth: Infinity }}>
        <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
          <Text font="caption1" foregroundStyle="secondaryLabel">内地 · 参考 20 GB</Text>
          <Text font="headline" monospacedDigit foregroundStyle="label">
            {mainland ? mainland.totalGB.toFixed(2) : "--"} GB
          </Text>
        </VStack>
        <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
          <Text font="caption1" foregroundStyle="secondaryLabel">非内地 · 参考 200 GB</Text>
          <Text font="headline" monospacedDigit foregroundStyle="label">
            {nonMainland ? nonMainland.totalGB.toFixed(2) : "--"} GB
          </Text>
        </VStack>
      </HStack>
      {unknown && unknown.totalBytes > 0 ? (
        <Text font="caption1" foregroundStyle="systemOrange">
          另有 {unknown.totalGB.toFixed(2)} GB 地域未识别，未计入上述分项
        </Text>
      ) : null}
    </VStack>
  )
}

// ==================== 5. 设置配置面板视图 ====================

function maskAccessKeyId(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) return ""

  const suffixLength = Math.min(4, Math.max(0, trimmed.length - 1))
  const suffix = suffixLength > 0 ? trimmed.slice(-suffixLength) : ""
  return `••••${suffix}`
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

function SettingsView({
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
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || 200))
  const [cutoffReference, setCutoffReference] = useState(
    String(currentConfig.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB)
  )
  const [errorNotice, setErrorNotice] = useState<string | null>(null)
  const [successNotice, setSuccessNotice] = useState<string | null>(null)
  const [accountName, setAccountName] = useState(currentConfig.name || "")
  const [site, setSite] = useState(currentConfig.site === "intl" ? "intl" : "cn")

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

  const handleSelectSite = async () => {
    if (typeof Dialog === "undefined" || !Dialog.actionSheet) {
      setSite(site === "intl" ? "cn" : "intl")
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
    if (idx === 0) setSite("cn")
    else if (idx === 1) setSite("intl")
  }

  const handleDelete = async () => {
    if (!onDelete || !currentConfig.id) return
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
    if (confirmed) onDelete(currentConfig.id)
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
      resetDayOfMonth: 1,
      id: currentConfig.id || newAccountId(),
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
  const deleteRow = onDelete && currentConfig.id ? (
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

// ==================== 6. 控制台仪表盘主视图 ====================

function getCachedConsoleSnapshot(config: AppConfig): { data: ConsoleData | null; lastUpdated: Date | null } {
  try {
    if (typeof Storage !== "undefined" && Storage?.get) {
      // 先读本账号快照；旧版未分账号的键仍可兜底，readSnapshot 会校验账号指纹。
      const scoped = Storage.get(scopedStorageKey(SNAPSHOT_STORAGE_KEY, config))
      const raw = readSnapshot(scoped, config) ? scoped : Storage.get(SNAPSHOT_STORAGE_KEY)
      if (raw) {
        const parsed = readSnapshot<ConsoleData>(raw, config)
        if (!parsed) return { data: null, lastUpdated: null }
        const now = new Date()
        parsed.isCached = true
        parsed.thresholdGB = config.trafficThresholdGB > 0 ? config.trafficThresholdGB : DEFAULT_CONFIG.trafficThresholdGB
        parsed.vpsCutoffReferenceGB = config.vpsCutoffReferenceGB > 0 ? config.vpsCutoffReferenceGB : DEFAULT_CONFIG.vpsCutoffReferenceGB
        parsed.cutoffRemainingGB = Math.max(0, Number((parsed.vpsCutoffReferenceGB - parsed.totalGB).toFixed(2)))
        parsed.remainingGB = Math.max(0, Number((parsed.thresholdGB - parsed.totalGB).toFixed(2)))
        parsed.percentage = usagePercentage(parsed.totalGB, parsed.thresholdGB)
        const progress = chinaMonthProgress(now)
        parsed.daysRemaining = progress.daysRemaining
        parsed.monthTimeProgress = progress.monthTimeProgress
        parsed.dailyBudgetGB = (parsed.remainingGB / parsed.daysRemaining).toFixed(2)
        if (parsed.financialBillStatus !== "available") {
          parsed.financialBillStatus = "unavailable"
        }
        if (parsed.previousFinancialBillStatus !== "available") {
          parsed.previousFinancialBillStatus = "unavailable"
        }
        if (!Array.isArray(parsed.financialBillHistory)) {
          parsed.financialBillHistory = []
          if (parsed.financialBill?.billingCycle) {
            parsed.financialBillHistory.push({
              billingCycle: parsed.financialBill.billingCycle,
              paymentAmount: parsed.financialBill.paymentAmount || "0.00",
              currency: parsed.financialBill.currency || "CNY",
              available: parsed.financialBillStatus === "available",
              hasRecords: true,
              paymentScope: parsed.financialBill.paymentScope
            })
          }
          if (parsed.previousFinancialBill?.billingCycle) {
            parsed.financialBillHistory.push({
              billingCycle: parsed.previousFinancialBill.billingCycle,
              paymentAmount: parsed.previousFinancialBill.paymentAmount || "0.00",
              currency: parsed.previousFinancialBill.currency || "CNY",
              available: parsed.previousFinancialBillStatus === "available",
              hasRecords: true,
              paymentScope: parsed.previousFinancialBill.paymentScope
            })
          }
        } else {
          parsed.financialBillHistory = parsed.financialBillHistory.map(item => ({
            ...item,
            available: item.available !== false,
            hasRecords: item.hasRecords !== false
          }))
        }
        for (const list of [parsed.financialBill?.ecsDailyList, parsed.financialBill?.eipDailyList]) {
          for (const item of list || []) {
            if (typeof item.available !== "boolean") item.available = false
          }
        }
        const ts = parsed.updatedAt instanceof Date ? parsed.updatedAt : parsed.updatedAt ? new Date(parsed.updatedAt) : null
        return { data: parsed, lastUpdated: ts }
      }
    }
  } catch {}
  return { data: null, lastUpdated: null }
}

function ConsoleView() {
  const [config, setConfig] = useState<AppConfig>(loadSavedConfig())
  const [showSettings, setShowSettings] = useState(!isConfigReady(config))
  const [refreshGate] = useState(() => createRefreshGate())
  const initialCache = getCachedConsoleSnapshot(config)
  const [data, setData] = useState<ConsoleData | null>(initialCache.data)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(initialCache.lastUpdated)
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [logs, setLogs] = useState<Array<{ line: string; financial: boolean }>>([])
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

  const appendLog = (msg: string, financial: boolean = false) => {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [{ line: `[${time}] ${msg}`, financial }, ...prev.slice(0, 7)])
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

  const handleShowBillHistory = async () => {
    try {
      if (typeof Haptic !== "undefined" && (Haptic as any)?.impact) {
        ;(Haptic as any).impact("light")
      }
    } catch {}

    const history = data?.financialBillHistory || []
    const currentDate = new Date()
    const currentCycle = chinaMonthKey(currentDate)
    const previousCycle = chinaMonthKey(currentDate, -1)
    const lines = history.map(item => {
      const amount = !item.available
        ? "查询不可用"
        : item.hasRecords === false
          ? "暂无记录"
          : isPrivacy
            ? "****"
            : `${currencySymbol(item.currency)}${item.paymentAmount}`
      const label = item.billingCycle === currentCycle
        ? "本月累计"
        : item.billingCycle === previousCycle
          ? "上月账期"
          : "历史账期"
      const scope = item.available && item.hasRecords !== false
        ? item.paymentScope === "allProducts"
          ? " · 全部产品"
          : item.paymentScope === "monitoredProducts"
            ? " · 监控产品"
            : " · 费用范围未标记"
        : ""
      return `${item.billingCycle}  ${label}：${amount}${scope}`
    })

    const message = [
      lines.length > 0 ? lines.join("\n") : "暂无近期账单快照，请刷新后重试。",
      "",
      "金额来自阿里云 BSS 账期账单，不是银行卡或余额的实际扣款流水。本月数据可能延迟；已结束月份也可能尚未完成出账，以阿里云账单中心为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({ title: "近期账单", message })
    }
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
      : !data?.financialBill
        ? "暂无记录"
      : isPrivacy
        ? "****"
        : `${currencySymbol(data.financialBill.currency)}${data.financialBill.ecsAmount}`
    const lines = list.map(item => {
      const amt = item.available === false
        ? "—"
        : isPrivacy
          ? "****"
          : `${currencySymbol(data?.financialBill?.currency)}${item.amount}`
      let tag = ""
      if (item.available === false) {
        tag = " (查询失败)"
      } else if (item.isToday) {
        tag = parseFloat(item.amount) > 0 ? " (今日查询结果)" : " (当前查询为0，非最终账单)"
      } else {
        tag = parseFloat(item.amount) > 0 ? " (查询到的费用)" : " (当前查询为0，非最终账单)"
      }
      return `${item.date}  ${amt}${tag}`
    })

    const msg = [
      `本月 ECS 产品账单查询结果: ${total}`,
      "说明：按账号维度汇总 ECS 产品费用，非当前配置的单台实例费用。",
      "",
      "【最近每日产品账单查询结果（可能延迟）】",
      lines.length > 0 ? lines.join("\n") : "暂无每日产品账单数据",
      "",
      data?.financialBillStatus === "unavailable"
        ? "账单接口暂不可用，请检查 BSS 权限或稍后刷新。"
        : "账单按产品分类汇总，不能归因到当前 ECS 实例；月内数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
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
    const total = data?.financialBillStatus === "unavailable"
      ? "暂不可用"
      : !data?.financialBill
        ? "暂无记录"
      : isPrivacy
        ? "****"
        : `${currencySymbol(data.financialBill.currency)}${data.financialBill.eipAmount}`
    const lines = list.map(item => {
      const amt = item.available === false
        ? "—"
        : isPrivacy
          ? "****"
          : `${currencySymbol(data?.financialBill?.currency)}${item.amount}`
      let tag = ""
      if (item.available === false) {
        tag = " (查询失败)"
      } else if (item.isToday) {
        tag = parseFloat(item.amount) > 0 ? " (今日查询结果)" : " (当前查询为0，非最终账单)"
      } else {
        tag = parseFloat(item.amount) > 0 ? " (查询到的费用)" : " (当前查询为0，非最终账单)"
      }
      return `${item.date}  ${amt}${tag}`
    })

    const msg = [
      `本月公网网络产品账单查询结果: ${total}`,
      "说明：按账号维度汇总公网网络产品费用，非当前配置公网 IP 的单独费用。",
      "",
      "【最近每日产品账单查询结果（可能延迟）】",
      lines.length > 0 ? lines.join("\n") : "暂无每日产品账单数据",
      "",
      data?.financialBillStatus === "unavailable"
        ? "账单接口暂不可用，请检查 BSS 权限或稍后刷新。"
        : "账单按产品分类汇总，不能归因到当前公网 IP；月内数据有延迟且仅供参考，最终金额以阿里云账单中心出账结果为准。"
    ].join("\n")

    if (typeof Dialog !== "undefined" && Dialog.alert) {
      await Dialog.alert({
        title: "公网网络费用明细",
        message: msg
      })
    }
  }

  const loadData = useCallback(
    async (cfg: AppConfig = config) => {
      const generation = refreshGate.start()
      if (!isConfigReady(cfg)) {
        setShowSettings(true)
        setLoading(false)
        return
      }
      setLoading(true)
      setErrorMessage(null)
      try {
        appendLog("正在连接阿里云 OpenAPI...")
        const res = await fetchConsoleData(cfg)
        if (!refreshGate.isCurrent(generation)) return
        const sampledAt = res.updatedAt instanceof Date ? res.updatedAt : new Date(res.updatedAt || "")
        assertSampleBillingMonth(sampledAt)
        recordTrafficSample(cfg, res.totalGB, sampledAt)
        res.isCached = false
        setData(res)
        setLastUpdated(sampledAt)
        try {
          if (typeof Storage !== "undefined" && Storage?.set) {
Storage.set(scopedStorageKey(SNAPSHOT_STORAGE_KEY, cfg), JSON.stringify(createSnapshot(cfg, res)))
            Storage.set(SNAPSHOT_STORAGE_KEY, JSON.stringify(createSnapshot(cfg, res)))
          }
        } catch {}
        appendLog(`CDT流量: ${res.totalGB} GB (${res.percentage}%)`)
        appendLog(`ECS 实例: ${res.ecsStatus} ${res.publicIp ? `(${res.publicIp})` : ""}`)
        if (res.financialBalance) {
          appendLog(`账户余额: ${currencySymbol(res.financialBalance.currency)}${res.financialBalance.availableCashAmount}`, true)
        }
      } catch (err: any) {
        if (!refreshGate.isCurrent(generation)) return
        const msg = humanizeAliyunError(err?.message || "网络请求失败，请检查配置")
        setErrorMessage(msg)
        const cached = getCachedConsoleSnapshot(cfg)
        setData(cached.data)
        setLastUpdated(cached.lastUpdated)
        appendLog(`错误: ${msg}`)
      } finally {
        if (refreshGate.isCurrent(generation)) setLoading(false)
      }
    },
    [config, refreshGate]
  )

  useEffect(() => {
    if (isConfigReady(config)) {
      loadData(config)
    }
    return () => refreshGate.invalidate()
  }, [])

  // 1. 如果正在打开设置页
  const switchAccount = (next: AppConfig) => {
    refreshGate.invalidate()
    try {
      if (typeof Storage !== "undefined" && Storage?.set) Storage.set(STORAGE_KEY, JSON.stringify(next))
    } catch {}
    const cached = getCachedConsoleSnapshot(next)
    setEditingNew(null)
    setConfig(next)
    setData(cached.data)
    setLastUpdated(cached.lastUpdated)
    setErrorMessage(null)
    setLogs([])
    setIsCopied(false)
    setShowSettings(false)
    loadData(next)
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
    setErrorMessage(null)
    setLogs([])
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
        <SettingsView
          key={(editingNew || config).id || "default"}
          currentConfig={editingNew || config}
          cancelable={editingNew ? isConfigReady(config) : undefined}
          onSave={newCfg => {
            refreshGate.invalidate()
            const cached = getCachedConsoleSnapshot(newCfg)
            setAccounts(loadAccountProfiles<AppConfig>(DEFAULT_CONFIG))
            setEditingNew(null)
            setConfig(newCfg)
            setData(cached.data)
            setLastUpdated(cached.lastUpdated)
            setErrorMessage(null)
            setLogs([])
            setIsCopied(false)
            setShowSettings(false)
            loadData(newCfg)
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
        ? "secondaryLabel"
        : errorMessage && !data
          ? "systemRed"
          : "secondaryLabel"

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
              : errorMessage
                ? "同步失败"
                : "等待同步"
  const statusLabel = data?.isCached ? `${observedStatusLabel}（缓存）` : observedStatusLabel
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
  const monthTimeProgress = data?.monthTimeProgress ?? chinaMonthProgress(now).monthTimeProgress
  const cutoffReferenceGB =
    data?.vpsCutoffReferenceGB || config.vpsCutoffReferenceGB || DEFAULT_CONFIG.vpsCutoffReferenceGB
  const cutoffRemainingGB = data?.cutoffRemainingGB ?? Math.max(0, cutoffReferenceGB - (data?.totalGB || 0))
  const healthMeta = data
    ? getTrafficHealthMeta(data.totalGB, cutoffReferenceGB, data.percentage, monthTimeProgress)
    : null

  // 2. 主控制台展示
  return (
    <NavigationStack>
      <ZStack
        frame={{ maxWidth: Infinity, maxHeight: Infinity }}
        navigationTitle={accounts.length > 1
          ? accountDisplayName(config, Math.max(0, accounts.findIndex(item => item.id === config.id)))
          : "阿里云 CDT"}
        navigationBarTitleDisplayMode="large"
        toolbarBackground="clear"
        toolbarBackgroundVisibility={{ visibility: "hidden", bars: ["navigationBar"] }}
        scrollEdgeEffectStyle={{ style: "soft", edges: "top" }}
        toolbar={{
          topBarLeading: [
            <Button key="dashboard-accounts" action={handleSwitchAccount} accessibilityLabel="切换账号">
              <Image systemName={accounts.length > 1 ? "person.2" : "person.crop.circle.badge.plus"} foregroundStyle="label" />
            </Button>,
          ],
          topBarTrailing: [
            <Button
              key="dashboard-refresh"
              action={() => loadData(config)}
              disabled={loading}
              accessibilityLabel="刷新数据"
            >
              <Image systemName="arrow.clockwise" foregroundStyle="label" />
            </Button>,
            <Button
              key="dashboard-settings"
              action={() => setShowSettings(true)}
              accessibilityLabel="设置"
            >
              <Image systemName="gearshape" foregroundStyle="label" />
            </Button>,
          ],
        }}
      >
        <ScrollView
          background="systemGroupedBackground"
          showsIndicators={false}
          safeAreaPadding={{ bottom: true }}
        >
          <VStack
            alignment="leading"
            spacing={8}
            padding={{ horizontal: 16, top: 8, bottom: 20 }}
          >

          {errorMessage && (
            <HStack
              alignment="top"
              spacing={10}
              padding={{ horizontal: 16, vertical: 12 }}
              frame={{ maxWidth: Infinity, alignment: "leading" }}
              {...dashboardSurface(16)}
            >
              <Image
                systemName="exclamationmark.triangle.fill"
                font={15}
                foregroundStyle="systemRed"
              />
              <Text
                font="subheadline"
                foregroundStyle="label"
                lineLimit={3}
                frame={{ maxWidth: Infinity, alignment: "leading" }}
              >
                {errorMessage}
              </Text>
            </HStack>
          )}

          <VStack
            spacing={0}
            padding={{ horizontal: 18, vertical: 16 }}
            frame={{ maxWidth: Infinity, alignment: "leading" }}
            {...dashboardSurface(22)}
          >
            <MonthlyTrafficOverview
              data={data}
              thresholdGB={config.trafficThresholdGB}
              lastUpdated={lastUpdated}
              loading={loading}
            />
          </VStack>

          {/* Section 1: ECS 实例状态 */}
          <DashboardSectionHeader title="实例" detail={config.regionId} />

          {/* 内容容器：纯白不透明（HIG 分层法则，卡片严禁玻璃叠玻璃） */}
          <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
            {/* 实例信息行 */}
            <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12}>
              <IconTile systemName="server.rack" color="systemGreen" />
              <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="body" foregroundStyle="label">
                  ECS 云服务器
                </Text>
                <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>
                  {config.ecsInstanceId}
                </Text>
              </VStack>
              <HStack spacing={6} alignment="center">
                <Circle fill={statusColor} frame={{ width: 8, height: 8 }} />
                <Text font="subheadline" foregroundStyle="secondaryLabel">
                  {statusLabel}
                </Text>
              </HStack>
            </HStack>

            <Divider padding={{ leading: 58 }} />

            {/* IP 行：轻触复制 */}
            <Button
              action={handleCopyIp}
              buttonStyle="plain"
              accessibilityLabel="复制公网 IP 地址"
            >
              <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12}>
                <IconTile systemName={isCopied ? "checkmark" : "network"} color={isCopied ? "systemGreen" : "systemBlue"} />
                <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                  <Text font="body" foregroundStyle="label">
                    公网 IP 地址
                  </Text>
                  <Text font="footnote" monospacedDigit foregroundStyle={isCopied ? "systemGreen" : publicIpColor === "systemBlue" ? "secondaryLabel" : publicIpColor} lineLimit={1}>
                    {isCopied ? "已复制到剪贴板" : publicIpLabel}
                  </Text>
                </VStack>
                <Image
                  systemName={isCopied ? "checkmark.circle.fill" : "doc.on.doc"}
                  font={15}
                  foregroundStyle={isCopied ? "systemGreen" : "systemBlue"}
                />
              </HStack>
            </Button>
          </VStack>
          <SectionFootnote>
            状态来自阿里云只读查询；开关机与熔断由 VPS 脚本独立负责。
          </SectionFootnote>

          {/* Section 2: 账户资产与实时费用 (Apple Wallet HIG Card) */}
          {data && (
            <>
              <DashboardSectionHeader
                title="账户与费用"
                trailing={
                  <Button action={togglePrivacy} buttonStyle="plain" accessibilityLabel={isPrivacy ? "显示金额" : "隐藏金额"}>
                    <HStack spacing={4} alignment="center">
                      <Image systemName={isPrivacy ? "eye.slash" : "eye"} font={13} foregroundStyle="systemBlue" />
                      <Text font="footnote" foregroundStyle="systemBlue">
                        {isPrivacy ? "显示" : "隐藏"}
                      </Text>
                    </HStack>
                  </Button>
                }
              />

              <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
                <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="top">
                  {/* 可用现金余额 */}
                  <Button
                    action={handleShowBillHistory}
                    buttonStyle="plain"
                    accessibilityLabel="查看最近四个月的账期费用"
                    frame={{ maxWidth: Infinity }}
                  >
                    <VStack alignment="leading" spacing={4} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                      <HStack alignment="center" spacing={4}>
                        <Text font="footnote" foregroundStyle="secondaryLabel">
                          账户现金余额
                        </Text>
                        <Image systemName="chevron.right" font={9} foregroundStyle="tertiaryLabel" />
                      </HStack>
                      {data.financialBalance ? (
                        <>
                          <HStack alignment="lastTextBaseline" spacing={3}>
                            <Text font="headline" foregroundStyle={data.financialBalance.status === "arrears" ? "systemRed" : "label"}>
                              {currencySymbol(data.financialBalance.currency)}
                            </Text>
                            <Text font={26} fontWeight="bold" monospacedDigit foregroundStyle={data.financialBalance.status === "arrears" ? "systemRed" : "label"} lineLimit={1} minScaleFactor={0.65}>
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
                              font="caption1"
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
                        </>
                      ) : (
                        <>
                          <Text font={26} fontWeight="bold" monospacedDigit foregroundStyle="secondaryLabel">
                            不可用
                          </Text>
                          <Text font="caption1" foregroundStyle="systemOrange">
                            余额查询不可用
                          </Text>
                        </>
                      )}
                    </VStack>
                  </Button>
                  <Divider frame={{ height: 56 }} />

                  {/* 当月账单查询结果 */}
                  <VStack alignment="leading" spacing={4} padding={{ leading: 16 }} frame={{ maxWidth: Infinity }}>
                    <Text font="footnote" foregroundStyle="secondaryLabel">
                      {financialBillPresentation.label}
                    </Text>
                    <HStack alignment="lastTextBaseline" spacing={3}>
                      {data.financialBillStatus === "available" && data.financialBill && (
                        <Text font="headline" foregroundStyle="label">
                          {currencySymbol(data.financialBill.currency)}
                        </Text>
                      )}
                      <Text font={26} fontWeight="bold" monospacedDigit foregroundStyle="label">
                        {data.financialBillStatus === "unavailable"
                          ? "不可用"
                          : !data.financialBill
                            ? "暂无记录"
                            : isPrivacy
                              ? "****"
                              : data.financialBill.paymentAmount}
                      </Text>
                    </HStack>
                    <Text
                      font="caption1"
                      lineLimit={2}
                      foregroundStyle={
                        data.financialBillStatus === "unavailable"
                          ? "systemOrange"
                          : !data.financialBill
                            ? "secondaryLabel"
                          : data.financialBill && parseFloat(data.financialBill.paymentAmount) > 0
                            ? "systemOrange"
                            : "systemGreen"
                      }
                    >
                      {data.financialBillStatus === "unavailable"
                        ? "账单查询不可用"
                        : !data.financialBill
                          ? "本月暂无可展示账单记录"
                          : financialBillPresentation.detail}
                    </Text>
                  </VStack>
                </HStack>

                <Divider padding={{ horizontal: 16 }} />

                <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12}>
                  <IconTile systemName="calendar" color="systemRed" />
                  <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                    <Text font="body" foregroundStyle="label">上月已出账费用</Text>
                    <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1} minScaleFactor={0.8}>
                      {data.previousFinancialBill?.billingCycle || "上一账期"} · {data.previousFinancialBillStatus === "available"
                        ? data.previousFinancialBill
                          ? "账号全部产品账单 · 出账可能延迟"
                          : "接口可用但暂无账单明细"
                        : "账单查询不可用"}
                    </Text>
                  </VStack>
                  <Text font="body" monospacedDigit lineLimit={1} minScaleFactor={0.65} foregroundStyle="secondaryLabel">
                    {data.previousFinancialBillStatus === "available" && data.previousFinancialBill
                      ? isPrivacy
                        ? "****"
                        : `${currencySymbol(data.previousFinancialBill.currency)}${data.previousFinancialBill.paymentAmount}`
                        : data.previousFinancialBillStatus === "available"
                          ? "暂无记录"
                          : "不可用"}
                  </Text>
                </HStack>

                <Divider padding={{ leading: 58 }} />

                {/* ECS 与公网网络产品费用（轻触查看每日分类） */}
                <Button action={handleShowEcsDaily} buttonStyle="plain" accessibilityLabel="查看 ECS 产品每日费用明细" frame={{ maxWidth: Infinity }}>
                  <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center" spacing={12} frame={{ maxWidth: Infinity }}>
                    <IconTile systemName="server.rack" color="systemBlue" />
                    <Text font="body" foregroundStyle="label" frame={{ maxWidth: Infinity, alignment: "leading" }}>ECS 产品</Text>
                    <Text font="body" monospacedDigit lineLimit={1} foregroundStyle="secondaryLabel">
                      {data.financialBillStatus === "unavailable"
                        ? "—"
                        : !data.financialBill
                          ? "暂无"
                          : isPrivacy
                            ? "****"
                            : `${currencySymbol(data.financialBill.currency)}${data.financialBill.ecsAmount}`}
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
                      {data.financialBillStatus === "unavailable"
                        ? "—"
                        : !data.financialBill
                          ? "暂无"
                          : isPrivacy
                            ? "****"
                            : `${currencySymbol(data.financialBill.currency)}${data.financialBill.eipAmount}`}
                    </Text>
                    <Image systemName="chevron.right" font={13} fontWeight="semibold" foregroundStyle="tertiaryLabel" />
                  </HStack>
                </Button>
              </VStack>
              <SectionFootnote>
                可用余额是当前账户资金；轻触余额查看近期账期费用，轻触产品查看最近每日分类。账单不代表余额扣款流水。
              </SectionFootnote>
            </>
          )}

          {/* Section 2: CDT 参考进度 */}
          <DashboardSectionHeader title="用量详情" detail={data ? `已用 ${data.percentage.toFixed(1)}%` : undefined} />

          <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
            {data && healthMeta && (
              <>
                <HStack spacing={12} alignment="center" padding={{ horizontal: 16, vertical: 11 }}>
                  <IconTile systemName={healthMeta.icon.replace(/\.(circle|octagon)\.fill$/, "")} color={healthMeta.color} />
                  <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                    <Text font="body" foregroundStyle="label" lineLimit={2}>
                      {healthMeta.label}
                    </Text>
                    <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1} minScaleFactor={0.8}>
                      本月时间已过 {monthTimeProgress.toFixed(0)}% · 流量已用 {data.percentage.toFixed(1)}% · VPS 线余 {formatCompactUsage(cutoffRemainingGB)} GB
                    </Text>
                  </VStack>
                </HStack>
                <Divider padding={{ leading: 58 }} />
              </>
            )}

            {data ? (
              <HStack padding={{ horizontal: 16, vertical: 14 }} alignment="center" spacing={0}>
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>
                    {data.totalGB > data.thresholdGB ? "超出参考值" : "参考余量"}
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={22} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.7} foregroundStyle={data.totalGB > data.thresholdGB ? "systemRed" : "label"}>
                      {data.totalGB > data.thresholdGB ? `+${formatCompactUsage(data.totalGB - data.thresholdGB)}` : formatCompactUsage(data.remainingGB)}
                    </Text>
                    <Text font="caption1" foregroundStyle="secondaryLabel">GB</Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 36 }} />

                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>
                    距结算
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={22} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.7} foregroundStyle="label">
                      {data.daysRemaining}
                    </Text>
                    <Text font="caption1" foregroundStyle="secondaryLabel">天</Text>
                  </HStack>
                </VStack>

                <Divider frame={{ height: 36 }} />

                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font="footnote" foregroundStyle="secondaryLabel" lineLimit={1}>
                    日均可用
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={22} fontWeight="semibold" monospacedDigit lineLimit={1} minScaleFactor={0.7} foregroundStyle="label">
                      {formatCompactUsage(Number(data.dailyBudgetGB))}
                    </Text>
                    <Text font="caption1" foregroundStyle="secondaryLabel">GB</Text>
                  </HStack>
                </VStack>
              </HStack>
            ) : (
              <HStack padding={16} alignment="center">
                <Text font="footnote" foregroundStyle="secondaryLabel">
                  正在同步阿里云最新用量数据...
                </Text>
              </HStack>
            )}
          </VStack>
          <SectionFootnote>
            VPS 独立负责实例保活与熔断，手机只读展示。流量余量和进度按本地月用量参考值计算，不代表阿里云账号维度的完整免费额度余额。
          </SectionFootnote>

          {data?.trafficDiagnostics && (
            <>
              <DashboardSectionHeader title="CDT 地域额度" detail="只读 · 按地域映射" />
              <VStack spacing={0} frame={{ maxWidth: Infinity, alignment: "leading" }} {...dashboardSurface()}>
                {(["mainland", "nonMainland", "unknown"] as CDTTrafficBucket[]).map((bucket, index) => {
                  const summary = data.trafficDiagnostics!.buckets[bucket]
                  const label = bucket === "mainland"
                    ? "内地 · 20 GB参考线"
                    : bucket === "nonMainland"
                      ? "非内地 · 200 GB参考线"
                      : "未识别 · 不套额度"
                  return (
                    <VStack key={bucket} spacing={0}>
                      {index > 0 && <Divider padding={{ leading: 16 }} />}
                      <HStack padding={{ horizontal: 16, vertical: 11 }} alignment="center">
                        <Text font="body" foregroundStyle="label" lineLimit={1}>{label}</Text>
                        <Spacer />
                        <Text font="subheadline" monospacedDigit foregroundStyle="secondaryLabel" lineLimit={1} minScaleFactor={0.75}>
                          {summary.totalGB.toFixed(2)} GB
                          {bucket !== "unknown" ? ` / ${bucket === "mainland" ? 20 : 200} GB` : ""}
                          {" · "}{summary.itemCount} 条
                        </Text>
                      </HStack>
                    </VStack>
                  )
                })}
                {data.trafficDiagnostics.groups.slice(0, 6).map((group, index) => (
                  <VStack key={`${group.bucket}-${group.businessRegionId || "none"}-${group.ispType || "none"}-${index}`} spacing={0}>
                    <Divider padding={{ leading: 16 }} />
                    <VStack alignment="leading" spacing={2} padding={{ horizontal: 16, vertical: 9 }} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                      <Text font="subheadline" foregroundStyle="label">
                        {group.bucket === "mainland"
                          ? "内地分组"
                          : group.bucket === "nonMainland"
                            ? "非内地分组"
                            : "未识别分组"} · {group.totalGB.toFixed(2)} GB
                      </Text>
                      <Text font="caption1" foregroundStyle="secondaryLabel" lineLimit={1} minScaleFactor={0.8}>
                        BusinessRegionId: {group.businessRegionId || "未返回"} · ISPType: {group.ispType || "未返回"}
                      </Text>
                    </VStack>
                  </VStack>
                ))}
              </VStack>
              <SectionFootnote>
                已按 BusinessRegionId 映射；未知值保留为未识别，不计入内地 20 GB 或非内地 200 GB。
              </SectionFootnote>
            </>
          )}

          {/* Section 3: 控制台实时操作日志 */}
          <DashboardSectionHeader
            title="最近活动"
            trailing={
              <Button
                action={() => setLogs([])}
                disabled={logs.length === 0}
                buttonStyle="plain"
                accessibilityLabel="清空日志"
              >
                <Text font="footnote" foregroundStyle={logs.length === 0 ? "tertiaryLabel" : "systemBlue"}>
                  清空
                </Text>
              </Button>
            }
          />

          {/* 日志容器：少量内容收缩，超过五行才使用固定视口滚动 */}
          <VStack
            spacing={0}
            padding={{ horizontal: 16, vertical: 12 }}
            frame={{ maxWidth: Infinity, height: logCardHeight, alignment: "leading" }}
            {...dashboardSurface()}
          >
            <ScrollView showsIndicators={false} frame={{ maxWidth: Infinity, height: logViewportHeight }}>
              <VStack alignment="leading" spacing={7} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                {logs.length > 0 ? (
                  logs.map((entry, index) => {
                    const parts = splitLogLine(entry.line)
                    return (
                      <HStack key={index} spacing={8} alignment="firstTextBaseline" frame={{ maxWidth: Infinity, alignment: "leading" }}>
                        <Text font="caption1" monospacedDigit foregroundStyle="tertiaryLabel">
                          {parts.time}
                        </Text>
                        <Text
                          font="footnote"
                          foregroundStyle={logMessageColor(entry.line)}
                          lineLimit={2}
                          frame={{ maxWidth: Infinity, alignment: "leading" }}
                        >
                          {isPrivacy && entry.financial ? "账户余额: ****" : parts.message}
                        </Text>
                      </HStack>
                    )
                  })
                ) : (
                  <Text font="footnote" foregroundStyle="secondaryLabel">
                    暂无日志，点击刷新同步。
                  </Text>
                )}
              </VStack>
            </ScrollView>
          </VStack>
          <SectionFootnote>最近 8 条操作记录</SectionFootnote>

          {/* 版本与构建信息 */}
          <Text font="caption1" foregroundStyle="tertiaryLabel" frame={{ maxWidth: Infinity, alignment: "center" }} padding={{ top: 12 }}>
            Aliyun CDT Monitor v{APP_VERSION}
          </Text>
          </VStack>
        </ScrollView>
      </ZStack>
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
