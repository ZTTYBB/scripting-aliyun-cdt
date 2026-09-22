/**
 * ============================================================================
 * 阿里云 CDT 流量与 ECS 实例智控控制台 (iOS Scripting Console)
 * 文件名: index.tsx
 * ============================================================================
 * 通用版特性：
 * 1. 零硬编码：完全通过 UI 设置面板录入，自动持久化至本地 Storage
 * 2. 交互式控制台：实时 CDT 流量环/进度条、ECS 运行状态、一键开机/关机
 * 3. 完整设置界面：随时修改 AK/SK、地域、ECS 实例 ID、阈值及自动关机开关
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
  Toggle,
  Toolbar,
  ToolbarItem,
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

interface ConsoleData {
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

  // 3. 熔断保护
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

  const color = percentage >= 90 ? "systemRed" : percentage >= 70 ? "systemOrange" : "systemGreen"

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

async function executeECSAction(action: "start" | "stop", config: AppConfig) {
  const apiAction = action === "start" ? "StartInstance" : "StopInstance"
  await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, apiAction, "2014-05-26", config, {
    InstanceId: config.ecsInstanceId.trim(),
    ForceStop: false
  })
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
    const numThreshold = Number(threshold)
    if (!Number.isFinite(numThreshold) || numThreshold <= 0) {
      setErrorNotice("流量阈值必须是大于 0 的数字。")
      return
    }
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

        {/* 提示横幅 */}
        {errorNotice && (
          <HStack
            padding={{ horizontal: 16, vertical: 12 }}
            background="rgba(255, 59, 48, 0.10)"
            border={{ style: "rgba(255, 59, 48, 0.25)", width: 0.75 }}
            clipShape={{ type: "rect", cornerRadius: 16, style: "continuous" }}
          >
            <Text font="caption1" bold foregroundStyle="systemRed">
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
            <Text font="caption1" bold foregroundStyle="systemGreen">
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
                promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (LTAI 开头)", ak, "LTAI5xxxxxxxxxxx", setAk)
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
          凭据仅加密存储于您 iPhone 本机的隔离沙盒内，绝不上云或外泄。
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
              label="修改"
              accessibilityLabel="设置 ECS 地域"
              action={() =>
                promptField("设置 ECS 地域", "如 cn-hongkong, cn-hangzhou, cn-shanghai, ap-southeast-1 等", region, "cn-hongkong", setRegion)
              }
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
          确保 Region ID 与 ECS 实例所在的物理地域一致。
        </Text>

        {/* Section 4: 流量风控策略 */}
        <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
            流量风控策略
          </Text>
        </HStack>
        <VStack
          background="systemBackground"
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
              <Image systemName="speedometer" font={16} foregroundStyle="systemPurple" />
            </ZStack>
            <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold foregroundStyle="label">
                CDT 流量警戒阈值
              </Text>
              <Text font="caption2" foregroundStyle="systemOrange">
                {threshold || "180"} GB / 月
              </Text>
            </VStack>
            <SettingsActionButton
              label="修改"
              accessibilityLabel="设置 CDT 流量警戒阈值"
              action={() =>
                promptField("设置 CDT 流量警戒阈值 (GB)", "输入当月出网流量警戒值", threshold, "180", setThreshold)
              }
            />
          </HStack>

          <Divider padding={{ leading: 64 }} />

          {/* 自动熔断关机开关 */}
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
                超额自动关机防扣费
              </Text>
              <Text font="caption2" foregroundStyle="secondaryLabel">
                当出网流量达到阈值时自动停止 ECS
              </Text>
            </VStack>
            <Toggle
              isOn={autoStop}
              onToggle={() => setAutoStop(!autoStop)}
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 16 }}>
          当月 CDT 出网流量达到警戒线时，小组件与控制台将自动触发关机以防超额产生账单。
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
      </VStack>
    </ScrollView>
  )
}

// ==================== 6. 控制台仪表盘主视图 (Apple iOS 26 Liquid Glass System) ====================

function ConsoleView() {
  const [config, setConfig] = useState<AppConfig>(loadSavedConfig())
  const [showSettings, setShowSettings] = useState(!isConfigReady(config))
  const [data, setData] = useState<ConsoleData | null>(null)
  const [loading, setLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [logs, setLogs] = useState<string[]>([])

  const appendLog = (msg: string) => {
    const time = new Date().toLocaleTimeString()
    setLogs(prev => [`[${time}] ${msg}`, ...prev.slice(0, 7)])
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
        appendLog(`CDT流量: ${res.totalGB} GB (${res.percentage}%)`)
        appendLog(`ECS 实例: ${res.ecsStatus} ${res.publicIp ? `(${res.publicIp})` : ""}`)
      } catch (err: any) {
        const msg = err?.message || "网络请求失败，请检查配置"
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

  const handleAction = async (type: "start" | "stop") => {
    setActionLoading(true)
    const actionName = type === "start" ? "开机启动" : "停止关机"
    appendLog(`正在执行 ${actionName} 指令...`)
    try {
      await executeECSAction(type, config)
      appendLog(`${actionName} 请求已发送，正在同步最新状态...`)
      await loadData(config)
    } catch (err: any) {
      const msg = err?.message || "操作失败"
      setErrorMessage(msg)
      appendLog(`${actionName} 失败: ${msg}`)
    } finally {
      setActionLoading(false)
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
        await handleAction("stop")
      }
    } else if (typeof Dialog !== "undefined" && Dialog.alert) {
      await handleAction("stop")
    } else {
      await handleAction("stop")
    }
  }

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

  const isRunning = data?.ecsStatus === "Running"
  const statusLabel = loading && !data
    ? "同步中"
    : data?.ecsStatus === "Stopped"
      ? "已停止"
      : data?.ecsStatus || (errorMessage ? "同步失败" : "等待同步")
  const publicIpLabel = loading
    ? "获取中..."
    : errorMessage && !data
      ? "获取失败，点击刷新"
      : data?.publicIp || (data ? "未绑定公网 IP" : "等待同步")
  const publicIpColor = data?.publicIp ? "systemBlue" : errorMessage && !data ? "systemRed" : "secondaryLabel"
  const visibleLogRows = Math.max(1, Math.min(logs.length, 5))
  const logCardHeight = logs.length === 0 ? 72 : Math.min(160, 24 + visibleLogRows * 28)
  const logViewportHeight = Math.max(48, logCardHeight - 24)

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
          {/* 顶部标题与设置入口 */}
          <HStack alignment="center" padding={{ horizontal: 4, bottom: 2 }}>
            <HStack spacing={8} alignment="center">
              <ZStack
                frame={{ width: 32, height: 32 }}
                background="rgba(0, 122, 255, 0.10)"
                clipShape={{ type: "capsule" }}
              >
                <Image systemName="cloud.fill" font={16} foregroundStyle="systemBlue" />
              </ZStack>
              <Text font="title3" bold foregroundStyle="label">
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
                <Image systemName="gearshape.fill" font={13} foregroundStyle="systemBlue" />
                <Text font="caption1" bold foregroundStyle="systemBlue">设置</Text>
              </HStack>
            </Button>
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
                  <Circle fill={isRunning ? "systemGreen" : "secondaryLabel"} frame={{ width: 6, height: 6 }} />
                </ZStack>
                <Text font={12} bold foregroundStyle={isRunning ? "systemGreen" : "secondaryLabel"}>
                  {isRunning ? "运行中" : statusLabel}
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
                <Image systemName="network" font={16} foregroundStyle="systemBlue" />
              </ZStack>
              <VStack alignment="leading" spacing={3} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold foregroundStyle="label">
                  公网 IP 地址
                </Text>
                <Text font="caption2" foregroundStyle={publicIpColor} lineLimit={1}>
                  {publicIpLabel}
                </Text>
              </VStack>
            </HStack>

            <Divider padding={{ horizontal: 16 }} />

            {/* 开关机控制按钮行 (Apple iOS 26 Liquid Glass Capsules) */}
            <HStack
              spacing={12}
              padding={{ horizontal: 16, vertical: 14 }}
              frame={{ maxWidth: Infinity, alignment: "center" }}
            >
              {/* 停止实例按钮：运行中为淡红微光液态玻璃胶囊，停止时为幽灵按钮 */}
              <Button
                action={confirmStop}
                disabled={!isRunning || actionLoading}
                buttonStyle="plain"
                accessibilityLabel={actionLoading ? "正在停止实例" : "停止实例"}
                frame={{
                  maxWidth: Infinity,
                  minHeight: 44,
                  idealHeight: 44,
                  alignment: "center"
                }}
              >
                <HStack
                  spacing={7}
                  alignment="center"
                  frame={{
                    maxWidth: Infinity,
                    minHeight: 44,
                    idealHeight: 44,
                    alignment: "center"
                  }}
                  background={isRunning && !actionLoading ? "rgba(255, 59, 48, 0.09)" : "systemGray6"}
                  border={
                    isRunning && !actionLoading
                      ? { style: "rgba(255, 59, 48, 0.25)", width: 0.75 }
                      : { style: "systemGray4", width: 0.75 }
                  }
                  clipShape={{ type: "capsule" }}
                  shadow={
                    isRunning && !actionLoading
                      ? { color: "rgba(255, 59, 48, 0.15)", radius: 6, x: 0, y: 2 }
                      : undefined
                  }
                  {...(isRunning && !actionLoading ? liquidGlass(true) : {})}
                >
                  <Image
                    systemName="power"
                    font={15}
                    fontWeight="bold"
                    foregroundStyle={isRunning && !actionLoading ? "systemRed" : "secondaryLabel"}
                  />
                  <Text
                    font={14}
                    bold={isRunning && !actionLoading}
                    foregroundStyle={isRunning && !actionLoading ? "systemRed" : "secondaryLabel"}
                    lineLimit={1}
                    minScaleFactor={0.9}
                    allowsTightening={true}
                  >
                    {actionLoading ? "处理中..." : "停止实例"}
                  </Text>
                </HStack>
              </Button>

              {/* 启动实例按钮：已开机时为极简灰色幽灵按钮，已关机时激活翠绿液态玻璃胶囊 */}
              <Button
                action={() => handleAction("start")}
                disabled={isRunning || actionLoading}
                buttonStyle="plain"
                accessibilityLabel={actionLoading ? "正在启动实例" : "启动实例"}
                frame={{
                  maxWidth: Infinity,
                  minHeight: 44,
                  idealHeight: 44,
                  alignment: "center"
                }}
              >
                <HStack
                  spacing={7}
                  alignment="center"
                  frame={{
                    maxWidth: Infinity,
                    minHeight: 44,
                    idealHeight: 44,
                    alignment: "center"
                  }}
                  background={!isRunning && !actionLoading ? "rgba(52, 199, 89, 0.12)" : "systemGray6"}
                  border={
                    !isRunning && !actionLoading
                      ? { style: "rgba(52, 199, 89, 0.28)", width: 0.75 }
                      : { style: "systemGray4", width: 0.75 }
                  }
                  clipShape={{ type: "capsule" }}
                  shadow={
                    !isRunning && !actionLoading
                      ? { color: "rgba(52, 199, 89, 0.16)", radius: 6, x: 0, y: 2 }
                      : undefined
                  }
                  {...(!isRunning && !actionLoading ? liquidGlass(true) : {})}
                >
                  <Image
                    systemName="play"
                    font={14}
                    fontWeight="bold"
                    foregroundStyle={!isRunning && !actionLoading ? "systemGreen" : "secondaryLabel"}
                  />
                  <Text
                    font={14}
                    bold={!isRunning && !actionLoading}
                    foregroundStyle={!isRunning && !actionLoading ? "systemGreen" : "secondaryLabel"}
                    lineLimit={1}
                    minScaleFactor={0.9}
                    allowsTightening={true}
                  >
                    {actionLoading ? "处理中..." : "启动实例"}
                  </Text>
                </HStack>
              </Button>
            </HStack>
          </VStack>
          <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 4 }}>
            为防误触，停止实例需要进行二次弹窗确认后方可执行。
          </Text>

          {/* Section 2: CDT 流量用量卡片 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
              CDT 互联网出网流量
            </Text>
            <Spacer />
            {data && (
              <HStack
                padding={{ horizontal: 8, vertical: 3 }}
                background={data.percentage >= 90 ? "rgba(255, 59, 48, 0.10)" : "rgba(52, 199, 89, 0.10)"}
                clipShape={{ type: "capsule" }}
              >
                <Text font={12} bold foregroundStyle={data.percentage >= 90 ? "systemRed" : "systemGreen"}>
                  已用 {data.percentage}%
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
                  出网用量 / 阈值
                </Text>
                <Text font="caption2" foregroundStyle="secondaryLabel">
                  当月警戒阈值: {config.trafficThresholdGB} GB
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
              <VStack padding={{ horizontal: 16, top: 2, bottom: 16 }}>
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

            <Divider padding={{ horizontal: 16 }} />

            {/* 三列指标卡片 (通透布局，去灰底，数值加粗大字号，内边距 16px) */}
            {data ? (
              <HStack padding={{ horizontal: 16, vertical: 16 }} alignment="center">
                {/* 剩余可用 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    剩余可用
                  </Text>
                  <HStack alignment="lastTextBaseline" spacing={2}>
                    <Text font={20} bold foregroundStyle="systemBlue">
                      {data.remainingGB.toFixed(1)}
                    </Text>
                    <Text font={12} bold foregroundStyle="systemBlue">
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

                {/* 建议日均 */}
                <VStack alignment="center" spacing={4} frame={{ maxWidth: Infinity }}>
                  <Text font={12} foregroundStyle="secondaryLabel">
                    建议日均
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
            <Image systemName="shield.fill" font={12} foregroundStyle="secondaryLabel" />
            <Text
              font={12}
              foregroundStyle="secondaryLabel"
              lineLimit={3}
              frame={{ maxWidth: Infinity, alignment: "leading" }}
            >
              自动熔断：当出网流量达到 {config.trafficThresholdGB} GB 时将自动停止 ECS 实例防止产生账单。
            </Text>
          </HStack>

          {/* Section 3: 控制台实时操作日志 */}
          <HStack padding={{ leading: 8, bottom: 2 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundStyle="secondaryLabel">
              实时操作日志
            </Text>
            <Spacer />
            <Button
              action={() => loadData(config)}
              disabled={loading || actionLoading}
              buttonStyle="plain"
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
                <Image
                  systemName="arrow.clockwise"
                  font={12}
                  fontWeight="bold"
                  foregroundStyle="systemBlue"
                />
                <Text font={12} bold foregroundStyle="systemBlue">
                  {loading ? "同步中..." : "刷新"}
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
          <Text font={12} foregroundStyle="secondaryLabel" padding={{ leading: 8, bottom: 12 }}>
            最近 8 条操作记录
          </Text>
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
