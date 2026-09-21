/**
 * ============================================================================
 * 阿里云 CDT 流量监控 & ECS 智控【单文件通用版 (All-In-One)】
 * ============================================================================
 * 特性：
 * 1. 零硬编码凭据：所有人下载即可直接使用，首次打开自动弹出设置界面。
 * 2. 凭据仅存储在用户 iPhone 本机 Scripting Storage 中，安全可靠。
 * 3. 桌面小组件模式：自动根据小组件尺寸呈现小号 / 中号 / 锁屏组件。
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

async function toggleECS(action: "start" | "stop", config: AppConfig) {
  const apiAction = action === "start" ? "StartInstance" : "StopInstance"
  await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, apiAction, "2014-05-26", config, {
    InstanceId: config.ecsInstanceId.trim(),
    ForceStop: false
  })
}

// ==================== 4. 小组件渲染视图 ====================

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
  const isRunning = data.ecsStatus === "Running"

  return (
    <VStack
      alignment="leading"
      spacing={6}
      padding={{ horizontal: 14, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      {/* 顶部标题与状态 */}
      <HStack alignment="center">
        <HStack spacing={4} alignment="center">
          <Image systemName="cloud.fill" font={12} foregroundStyle="systemBlue" />
          <Text font="caption2" bold foregroundColor="#8E8E93">
            CDT 流量
          </Text>
        </HStack>
        <Spacer />
        <HStack spacing={4} alignment="center">
          <Circle fill={isRunning ? "#30D158" : "#8E8E93"} frame={{ width: 6, height: 6 }} />
          <Text font="caption2" bold foregroundColor={isRunning ? "#30D158" : "#8E8E93"}>
            {isRunning ? "运行中" : "已关机"}
          </Text>
        </HStack>
      </HStack>

      <Spacer />

      {/* 核心用量数据 */}
      <VStack alignment="leading" spacing={2}>
        <HStack alignment="bottom" spacing={2}>
          <Text font={24} bold foregroundColor={data.color}>
            {data.totalGB.toFixed(1)}
          </Text>
          <Text font="caption2" foregroundColor="#8E8E93" padding={{ bottom: 2 }}>
            / {data.thresholdGB}G
          </Text>
        </HStack>
        <Text font="caption2" foregroundColor="#8E8E93">
          已用 {data.percentage}% · 剩 {data.remainingGB.toFixed(1)}G
        </Text>
      </VStack>

      {/* 原生线性进度条 */}
      <ProgressView
        value={Math.max(0.01, Math.min(1.0, data.percentage / 100))}
        tint={data.color as any}
        frame={{ height: 5 }}
      />

      <Spacer />

      {/* 底部重置倒计时 */}
      <HStack alignment="center">
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

function MediumWidget({ data }: { data: MonitorData }) {
  const isRunning = data.ecsStatus === "Running"

  return (
    <VStack
      alignment="leading"
      spacing={8}
      padding={{ horizontal: 16, vertical: 12 }}
      widgetBackground="systemBackground"
      frame={{ maxWidth: Infinity, maxHeight: Infinity }}
    >
      {/* 顶部标题与 ECS 状态指示 */}
      <HStack alignment="center">
        <HStack spacing={6} alignment="center">
          <Image systemName="cloud.fill" font={14} foregroundStyle="systemBlue" />
          <Text font="headline" bold foregroundStyle="label">
            阿里云 CDT 监控
          </Text>
        </HStack>
        <Spacer />
        <HStack
          padding={{ top: 3, bottom: 3, leading: 8, trailing: 8 }}
          background="rgba(142, 142, 147, 0.15)"
          cornerRadius={12}
          spacing={5}
          alignment="center"
        >
          <Circle fill={isRunning ? "#30D158" : "#8E8E93"} frame={{ width: 7, height: 7 }} />
          <Text font={11} bold foregroundColor={isRunning ? "#30D158" : "#8E8E93"}>
            ECS {isRunning ? "运行中" : "已关机"}
          </Text>
        </HStack>
      </HStack>

      {/* 核心用量指标与百分比 */}
      <HStack alignment="bottom" spacing={6}>
        <Text font={28} bold foregroundColor={data.color}>
          {data.totalGB.toFixed(1)}
        </Text>
        <Text font="footnote" foregroundColor="#8E8E93" padding={{ bottom: 3 }}>
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

      {/* 原生线性进度条 */}
      <ProgressView
        value={Math.max(0.01, Math.min(1.0, data.percentage / 100))}
        tint={data.color as any}
        frame={{ height: 6 }}
      />

      <Spacer />

      {/* 底部详细信息栏 */}
      <HStack alignment="center" spacing={4}>
        <Text font="caption2" foregroundColor="#8E8E93">
          距结算重置:
        </Text>
        <Text font="caption2" bold foregroundColor="#0A84FF">
          {data.daysRemaining} 天
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

// ==================== 5. 设置视图 ====================

function SettingsComponent({
  currentConfig,
  onSave,
  onCancel
}: {
  currentConfig: AppConfig
  onSave: (newCfg: AppConfig) => void
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
            message: "请先在微信、备忘录中复制包含阿里云 AccessKey 或实例 ID 的文本，再点击智能识别。"
          })
        } else {
          setErrorNotice("剪贴板为空，请先复制凭据信息。")
        }
        return
      }

      let count = 0
      // 匹配 AccessKey ID: LTAI 开头，16-24 位字符
      const akMatch = text.match(/LTAI[A-Za-z0-9]{16,24}/i)
      if (akMatch) {
        setAk(akMatch[0].trim())
        count++
      }

      // 匹配 ECS 实例 ID: i- 开头，16-24 位字符
      const ecsMatch = text.match(/i-[a-z0-9]{16,24}/i)
      if (ecsMatch) {
        setEcsId(ecsMatch[0].trim())
        count++
      }

      // 匹配 Region ID
      const regMatch = text.match(/(cn-[a-z0-9-]+|ap-[a-z0-9-]+|us-[a-z0-9-]+)/i)
      if (regMatch) {
        setRegion(regMatch[0].trim())
      }

      // 匹配 AccessKey Secret (通常位于 Secret 关键字之后，或 28-34 位随机字符串)
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
    <ScrollView>
      <VStack alignment="leading" spacing={16} padding={16}>
        {/* 顶部导航 */}
        <HStack>
          <Text font="title2" bold>
            ⚙️ 阿里云参数配置
          </Text>
          <Spacer />
          {isConfigReady(currentConfig) && (
            <Button title="取消" font="subheadline" action={onCancel} />
          )}
        </HStack>

        <Text font="caption1" foregroundColor="#8E8E93">
          所有凭据仅保存在您手机本机的 Scripting 隔离存储空间中，绝不上云或外泄。
        </Text>

        {/* 快捷智能导入卡片 */}
        <HStack
          padding={12}
          background="rgba(10, 132, 255, 0.12)"
          cornerRadius={12}
          alignment="center"
        >
          <VStack alignment="leading" spacing={2} frame={{ maxWidth: "infinity", alignment: "leading" }}>
            <Text font="subheadline" bold foregroundColor="#0A84FF">
              📋 智能剪贴板识别
            </Text>
            <Text font="caption2" foregroundColor="#8E8E93">
              在手机上复制包含 AK、Secret、实例ID 的文本后点此自动填入
            </Text>
          </VStack>
          <Button
            title="一键识别"
            buttonStyle="borderedProminent"
            controlSize="regular"
            action={handleSmartPaste}
          />
        </HStack>

        {/* 错误提示条 */}
        {errorNotice && (
          <HStack padding={10} background="rgba(255, 69, 58, 0.12)" cornerRadius={8}>
            <Text font="caption2" foregroundColor="#FF453A">
              ⚠️ {errorNotice}
            </Text>
          </HStack>
        )}

        {/* 成功提示条 */}
        {successNotice && (
          <HStack padding={10} background="rgba(48, 209, 88, 0.12)" cornerRadius={8}>
            <Text font="caption2" foregroundColor="#30D158">
              {successNotice}
            </Text>
          </HStack>
        )}

        {/* 字段输入卡片列表 */}
        <VStack spacing={12} frame={{ maxWidth: "infinity" }}>
          {/* AccessKey ID */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={4} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="caption2" bold foregroundColor="#8E8E93">
                AccessKey ID (LTAI 开头)
              </Text>
              <Text
                font="subheadline"
                bold
                foregroundColor={ak ? "#FFFFFF" : "#0A84FF"}
                lineLimit={1}
              >
                {ak ? ak : "轻点右侧按钮输入 >"}
              </Text>
            </VStack>
            <Button
              title={ak ? "修改" : "输入"}
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (如 LTAI...)", ak, "LTAI5xxxxxxxxxxx", setAk)
              }
            />
          </HStack>

          {/* AccessKey Secret */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={4} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="caption2" bold foregroundColor="#8E8E93">
                AccessKey Secret
              </Text>
              <Text
                font="subheadline"
                bold
                foregroundColor={sk ? "#30D158" : "#0A84FF"}
                lineLimit={1}
              >
                {sk ? "••••••••••••••••••••••••••••" : "轻点右侧按钮输入 >"}
              </Text>
            </VStack>
            <Button
              title={sk ? "修改" : "输入"}
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 AccessKey Secret", "请输入阿里云 AccessKey Secret", sk, "您的 Secret Key", setSk)
              }
            />
          </HStack>

          {/* ECS 所在地域 */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={4} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="caption2" bold foregroundColor="#8E8E93">
                ECS 所在地域 (Region ID)
              </Text>
              <Text
                font="subheadline"
                bold
                foregroundColor="#FFFFFF"
                lineLimit={1}
              >
                {region || "cn-hongkong"}
              </Text>
            </VStack>
            <Button
              title="修改"
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 ECS 地域", "如 cn-hongkong, cn-hangzhou, cn-shanghai, ap-southeast-1 等", region, "cn-hongkong", setRegion)
              }
            />
          </HStack>

          {/* ECS 实例 ID */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={4} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="caption2" bold foregroundColor="#8E8E93">
                ECS 实例 ID (i- 开头)
              </Text>
              <Text
                font="subheadline"
                bold
                foregroundColor={ecsId ? "#FFFFFF" : "#0A84FF"}
                lineLimit={1}
              >
                {ecsId ? ecsId : "轻点右侧按钮输入 >"}
              </Text>
            </VStack>
            <Button
              title={ecsId ? "修改" : "输入"}
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 ECS 实例 ID", "请输入您要控制的 ECS 实例 ID (如 i-j6c...)", ecsId, "i-xxxxxxxxxxxx", setEcsId)
              }
            />
          </HStack>

          {/* CDT 流量警戒阈值 */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={4} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="caption2" bold foregroundColor="#8E8E93">
                CDT 流量警戒阈值 (GB)
              </Text>
              <Text font="subheadline" bold foregroundColor="#FF9F0A">
                {threshold || "180"} GB / 月
              </Text>
            </VStack>
            <Button
              title="修改"
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 CDT 流量警戒阈值 (GB)", "输入当月出网流量警戒值 (超出后告警或自动关机)", threshold, "180", setThreshold)
              }
            />
          </HStack>

          {/* 超额自动关机防扣费开关 */}
          <HStack
            padding={12}
            background="rgba(142, 142, 147, 0.12)"
            cornerRadius={10}
            alignment="center"
          >
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: "infinity", alignment: "leading" }}>
              <Text font="subheadline" bold>
                超额自动关机防扣费
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
                当出网流量超过警戒阈值时自动停止 ECS
              </Text>
            </VStack>
            <Button
              title={autoStop ? "🟢 已开启" : "⚪ 已关闭"}
              buttonStyle="bordered"
              controlSize="small"
              action={() => setAutoStop(!autoStop)}
            />
          </HStack>
        </VStack>

        <Spacer />

        {/* 底部保存按钮 */}
        <Button
          title="💾 保存配置并进入控制台"
          buttonStyle="borderedProminent"
          controlSize="large"
          action={handleSave}
        />
      </VStack>
    </ScrollView>
  )
}

// ==================== 6. 控制台视图 ====================

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
      <VStack
        alignment="leading"
        spacing={16}
        padding={16}
        navigationTitle="阿里云 CDT 智控中心"
      >
        <HStack>
          <Text font="headline" bold>
            🖥️ 实例控制
          </Text>
          <Spacer />
          <Button
            title="⚙️ 设置"
            font="footnote"
            buttonStyle="bordered"
            action={() => setShowSettings(true)}
          />
        </HStack>

        {errorMsg && (
          <HStack padding={12} background="rgba(255, 69, 58, 0.12)" cornerRadius={10}>
            <Text font="footnote" foregroundColor="#FF453A">
              ⚠️ {errorMsg}
            </Text>
          </HStack>
        )}

        {/* 流量监控卡片 */}
        <VStack
          alignment="leading"
          padding={16}
          background="rgba(142, 142, 147, 0.08)"
          cornerRadius={14}
          spacing={12}
        >
          <HStack>
            <Text font="headline" bold>
              📊 CDT 出网流量
            </Text>
            <Spacer />
            {data && (
              <Text font="footnote" bold foregroundColor={data.color}>
                {data.percentage}%
              </Text>
            )}
          </HStack>

          {data ? (
            <VStack alignment="leading" spacing={8}>
              <HStack alignment="bottom" spacing={6}>
                <Text font="largeTitle" bold foregroundColor={data.color}>
                  {data.totalGB.toFixed(2)}
                </Text>
                <Text font="subheadline" foregroundColor="#8E8E93" padding={{ bottom: 4 }}>
                  GB / {data.thresholdGB} GB
                </Text>
                <Spacer />
                <VStack alignment="trailing">
                  <Text font="caption1" foregroundColor="#8E8E93">
                    剩余可用
                  </Text>
                  <Text font="headline" bold foregroundColor="#0A84FF">
                    {data.remainingGB.toFixed(2)} GB
                  </Text>
                </VStack>
              </HStack>

              <ZStack alignment="leading">
                <HStack
                  frame={{ height: 8, maxWidth: "infinity" }}
                  background="rgba(142, 142, 147, 0.2)"
                  cornerRadius={4}
                />
                <HStack
                  frame={{
                    height: 8,
                    width: `${Math.max(2, Math.min(100, data.percentage))}%`
                  }}
                  background={data.color}
                  cornerRadius={4}
                />
              </ZStack>

              <HStack padding={{ top: 4 }}>
                <Text font="caption2" foregroundColor="#8E8E93">
                  距结算日: {data.daysRemaining} 天
                </Text>
                <Spacer />
                <Text font="caption2" foregroundColor="#8E8E93">
                  建议日均: &lt; {data.dailyBudgetGB} GB
                </Text>
              </HStack>
            </VStack>
          ) : (
            <Text font="subheadline" foregroundColor="#8E8E93">
              正在加载阿里云实时数据...
            </Text>
          )}
        </VStack>

        {/* ECS 控制卡片 */}
        <VStack
          alignment="leading"
          padding={16}
          background="rgba(142, 142, 147, 0.08)"
          cornerRadius={14}
          spacing={12}
        >
          <HStack>
            <Text font="headline" bold>
              🖥️ ECS 运行状态
            </Text>
            <Spacer />
            {data && (
              <HStack
                padding={{ top: 3, bottom: 3, leading: 8, trailing: 8 }}
                background={isRunning ? "rgba(48, 209, 88, 0.15)" : "rgba(255, 69, 58, 0.15)"}
                cornerRadius={12}
                spacing={4}
              >
                <Text font="caption1">{isRunning ? "🟢" : "🔴"}</Text>
                <Text
                  font="caption1"
                  bold
                  foregroundColor={isRunning ? "#30D158" : "#FF453A"}
                >
                  {isRunning ? "运行中" : "已关机"}
                </Text>
              </HStack>
            )}
          </HStack>

          <VStack alignment="leading" spacing={4}>
            <HStack>
              <Text font="footnote" foregroundColor="#8E8E93">
                实例 ID:
              </Text>
              <Text font="footnote" bold>
                {config.ecsInstanceId}
              </Text>
            </HStack>
            {data?.publicIp && (
              <HStack>
                <Text font="footnote" foregroundColor="#8E8E93">
                  公网 IP:
                </Text>
                <Text font="footnote" bold foregroundColor="#0A84FF">
                  {data.publicIp}
                </Text>
              </HStack>
            )}
          </VStack>

          <Divider />

          <HStack spacing={12}>
            <Button
              title="停止实例 (关机)"
              disabled={!isRunning || btnLoading}
              buttonStyle="bordered"
              tint="#FF453A"
              action={() => handleToggle("stop")}
            />
            <Button
              title="启动实例 (开机)"
              disabled={isRunning || btnLoading}
              buttonStyle="borderedProminent"
              tint="#30D158"
              action={() => handleToggle("start")}
            />
          </HStack>
        </VStack>

        <Spacer />

        <VStack alignment="center" spacing={8}>
          <Button
            title={loading ? "刷新中..." : "🔄 刷新数据"}
            buttonStyle="bordered"
            disabled={loading}
            action={() => refresh(config)}
          />
        </VStack>
      </VStack>
    </NavigationStack>
  )
}

// ==================== 7. 执行分流 (Widget 还是 App) ====================

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
      if (Widget.family === "systemMedium" || Widget.family === "systemLarge") {
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
