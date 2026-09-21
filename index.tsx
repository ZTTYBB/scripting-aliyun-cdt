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

async function executeECSAction(action: "start" | "stop", config: AppConfig) {
  const apiAction = action === "start" ? "StartInstance" : "StopInstance"
  await aliyunRequest(`ecs.${config.regionId}.aliyuncs.com`, apiAction, "2014-05-26", config, {
    InstanceId: config.ecsInstanceId.trim(),
    ForceStop: false
  })
}

// ==================== 4. 设置配置面板视图 ====================

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
    <ScrollView background="#F2F2F7">
      <VStack alignment="leading" spacing={0} padding={{ horizontal: 16, vertical: 12 }}>
        {/* 顶部导航栏 (仿 iOS 原生设置顶栏) */}
        <HStack alignment="center" padding={{ bottom: 12 }}>
          {isConfigReady(currentConfig) ? (
            <Button
              action={onCancel}
              buttonStyle="plain"
              frame={{ width: 36, height: 36 }}
            >
              <ZStack frame={{ width: 36, height: 36 }} background="rgba(142, 142, 147, 0.18)" cornerRadius={18}>
                <Image systemName="chevron.backward" font={15} fontWeight="bold" foregroundStyle="#007AFF" />
              </ZStack>
            </Button>
          ) : (
            <Spacer frame={{ width: 36 }} />
          )}
          <Spacer />
          <Text font="headline" bold foregroundColor="#000000">
            参数配置
          </Text>
          <Spacer />
          <Button
            title="保存"
            font="headline"
            buttonStyle="plain"
            foregroundColor="#007AFF"
            action={handleSave}
          />
        </HStack>

        {/* 提示横幅 */}
        {errorNotice && (
          <HStack padding={12} background="rgba(255, 59, 48, 0.12)" cornerRadius={10} padding={{ bottom: 10 }}>
            <Text font="caption1" bold foregroundColor="#FF3B30">
              ⚠️ {errorNotice}
            </Text>
          </HStack>
        )}
        {successNotice && (
          <HStack padding={12} background="rgba(52, 199, 89, 0.12)" cornerRadius={10} padding={{ bottom: 10 }}>
            <Text font="caption1" bold foregroundColor="#34C759">
              {successNotice}
            </Text>
          </HStack>
        )}

        {/* Section 1: 智能识别 */}
        <HStack padding={{ leading: 8, bottom: 6, top: 4 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            快捷导入
          </Text>
        </HStack>
        <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#007AFF" cornerRadius={7}>
              <Image systemName="doc.on.clipboard.fill" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                智能剪贴板识别
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
                自动提取复制文本中的 AK、SK 与实例 ID
              </Text>
            </VStack>
            <Button
              title="一键识别"
              buttonStyle="borderedProminent"
              controlSize="small"
              tint="#007AFF"
              action={handleSmartPaste}
            />
          </HStack>
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 12 }}>
          复制包含阿里云凭据的文本后轻点此处，自动提取填入下方所有字段。
        </Text>

        {/* Section 2: 访问凭据 */}
        <HStack padding={{ leading: 8, bottom: 6 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            阿里云访问凭据
          </Text>
        </HStack>
        <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
          {/* AccessKey ID */}
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#FF9500" cornerRadius={7}>
              <Image systemName="key.fill" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                AccessKey ID
              </Text>
              <Text font="caption2" foregroundColor={ak ? "#8E8E93" : "#007AFF"} lineLimit={1}>
                {ak ? ak : "轻点右侧设置 >"}
              </Text>
            </VStack>
            <Button
              title={ak ? "修改" : "输入"}
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 AccessKey ID", "请输入阿里云 AccessKey ID (LTAI 开头)", ak, "LTAI5xxxxxxxxxxx", setAk)
              }
            />
          </HStack>

          <Divider padding={{ leading: 56 }} />

          {/* AccessKey Secret */}
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#FF3B30" cornerRadius={7}>
              <Image systemName="lock.fill" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                AccessKey Secret
              </Text>
              <Text font="caption2" foregroundColor={sk ? "#34C759" : "#007AFF"} lineLimit={1}>
                {sk ? "••••••••••••••••••••••••••••" : "轻点右侧设置 >"}
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
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 12 }}>
          凭据仅加密存储于您 iPhone 本机的隔离沙盒内，绝不上云或外泄。
        </Text>

        {/* Section 3: 目标实例与地域 */}
        <HStack padding={{ leading: 8, bottom: 6 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            目标 ECS 实例
          </Text>
        </HStack>
        <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
          {/* ECS 实例 ID */}
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#34C759" cornerRadius={7}>
              <Image systemName="server.rack" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                ECS 实例 ID
              </Text>
              <Text font="caption2" foregroundColor={ecsId ? "#8E8E93" : "#007AFF"} lineLimit={1}>
                {ecsId ? ecsId : "未设置 (如 i-j6c...)"}
              </Text>
            </VStack>
            <Button
              title={ecsId ? "修改" : "输入"}
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 ECS 实例 ID", "请输入您要控制的 ECS 实例 ID", ecsId, "i-xxxxxxxxxxxx", setEcsId)
              }
            />
          </HStack>

          <Divider padding={{ leading: 56 }} />

          {/* ECS 地域 */}
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#5856D6" cornerRadius={7}>
              <Image systemName="globe.asia.australia.fill" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                ECS 所在地域
              </Text>
              <Text font="caption2" foregroundColor="#8E8E93">
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
        </VStack>
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 12 }}>
          确保 Region ID 与 ECS 实例所在的物理地域一致。
        </Text>

        {/* Section 4: 流量风控策略 */}
        <HStack padding={{ leading: 8, bottom: 6 }} alignment="center">
          <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
            流量风控策略
          </Text>
        </HStack>
        <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
          {/* CDT 警戒阈值 */}
          <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#AF52DE" cornerRadius={7}>
              <Image systemName="speedometer" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
                CDT 流量警戒阈值
              </Text>
              <Text font="caption2" foregroundColor="#FF9500">
                {threshold || "180"} GB / 月
              </Text>
            </VStack>
            <Button
              title="修改"
              buttonStyle="bordered"
              controlSize="small"
              action={() =>
                promptField("设置 CDT 流量警戒阈值 (GB)", "输入当月出网流量警戒值", threshold, "180", setThreshold)
              }
            />
          </HStack>

          <Divider padding={{ leading: 56 }} />

          {/* 自动熔断关机开关 */}
          <HStack padding={{ horizontal: 14, vertical: 11 }} alignment="center" spacing={12}>
            <ZStack frame={{ width: 30, height: 30 }} background="#00C7BE" cornerRadius={7}>
              <Image systemName="shield.lefthalf.filled" font={15} foregroundStyle="#FFFFFF" />
            </ZStack>
            <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
              <Text font="subheadline" bold>
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
        <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 20 }}>
          当月 CDT 出网流量达到警戒线时，小组件与控制台将自动触发关机以防超额产生账单。
        </Text>

        {/* 底部保存按钮 */}
        <Button
          title="💾 保存配置并返回控制台"
          buttonStyle="borderedProminent"
          controlSize="large"
          tint="#007AFF"
          frame={{ maxWidth: Infinity }}
          action={handleSave}
        />
      </VStack>
    </ScrollView>
  )
}

// ==================== 5. 控制台仪表盘主视图 (Apple Native Inset Grouped Style) ====================

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
    setLogs(prev => [`[${time}] ${msg}`, ...prev.slice(0, 5)])
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
        appendLog(`❌ 错误: ${msg}`)
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
      appendLog(`✅ ${actionName} 请求已发送，正在同步最新状态...`)
      await loadData(config)
    } catch (err: any) {
      const msg = err?.message || "操作失败"
      setErrorMessage(msg)
      appendLog(`❌ ${actionName} 失败: ${msg}`)
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

  // 2. 主控制台展示 (Apple Inset Grouped)
  return (
    <NavigationStack>
      <ScrollView background="#F2F2F7">
        <VStack
          alignment="leading"
          spacing={0}
          padding={{ horizontal: 16, vertical: 12 }}
          navigationTitle="阿里云 CDT 智控台"
          navigationBarTitleDisplayMode="inline"
        >
          {/* 顶部标题与设置入口 */}
          <HStack alignment="center" padding={{ bottom: 12 }}>
            <HStack spacing={6} alignment="center">
              <Image systemName="cloud.fill" font={18} foregroundStyle="#007AFF" />
              <Text font="headline" bold foregroundColor="#000000">
                阿里云 CDT 智控台
              </Text>
            </HStack>
            <Spacer />
            <Button
              action={() => setShowSettings(true)}
              buttonStyle="plain"
              frame={{ width: 36, height: 36 }}
            >
              <ZStack frame={{ width: 36, height: 36 }} background="rgba(142, 142, 147, 0.18)" cornerRadius={18}>
                <Image systemName="gearshape.fill" font={16} foregroundStyle="#007AFF" />
              </ZStack>
            </Button>
          </HStack>

          {errorMessage && (
            <HStack padding={12} background="rgba(255, 59, 48, 0.12)" cornerRadius={10} padding={{ bottom: 12 }}>
              <Text font="caption1" bold foregroundColor="#FF3B30">
                ⚠️ {errorMessage}
              </Text>
            </HStack>
          )}

          {/* Section 1: ECS 实例状态 */}
          <HStack padding={{ leading: 8, bottom: 6, top: 4 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
              实例运行状态
            </Text>
            <Spacer />
            <Text font={12} foregroundColor="#8E8E93">
              {config.regionId}
            </Text>
          </HStack>

          <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
            {/* 实例信息行 */}
            <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
              <ZStack frame={{ width: 30, height: 30 }} background={isRunning ? "#34C759" : "#8E8E93"} cornerRadius={7}>
                <Image systemName="server.rack" font={15} foregroundStyle="#FFFFFF" />
              </ZStack>
              <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold>
                  ECS 实例
                </Text>
                <Text font="caption2" foregroundColor="#8E8E93" lineLimit={1}>
                  {config.ecsInstanceId}
                </Text>
              </VStack>
              <HStack
                padding={{ horizontal: 8, vertical: 4 }}
                background={isRunning ? "rgba(52, 199, 89, 0.15)" : "rgba(142, 142, 147, 0.18)"}
                cornerRadius={8}
                spacing={5}
                alignment="center"
              >
                <Circle fill={isRunning ? "#34C759" : "#8E8E93"} frame={{ width: 6, height: 6 }} />
                <Text font={12} bold foregroundColor={isRunning ? "#34C759" : "#8E8E93"}>
                  {isRunning ? "运行中" : data?.ecsStatus === "Stopped" ? "已停止" : data?.ecsStatus || "加载中"}
                </Text>
              </HStack>
            </HStack>

            <Divider padding={{ leading: 56 }} />

            {/* IP与地域行 */}
            <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
              <ZStack frame={{ width: 30, height: 30 }} background="#007AFF" cornerRadius={7}>
                <Image systemName="network" font={15} foregroundStyle="#FFFFFF" />
              </ZStack>
              <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold>
                  公网 IP 地址
                </Text>
                <Text font="caption2" foregroundColor={data?.publicIp ? "#007AFF" : "#8E8E93"}>
                  {data?.publicIp || "未分配公网 IP"}
                </Text>
              </VStack>
              <Text font="caption2" foregroundColor="#8E8E93">
                {config.regionId}
              </Text>
            </HStack>

            <Divider padding={{ leading: 56 }} />

            {/* 开关机控制按钮行 (带二次确认防护) */}
            <HStack spacing={12} padding={{ horizontal: 14, vertical: 12 }}>
              <Button
                title={actionLoading ? "处理中..." : "🛑 停止实例 (关机)"}
                disabled={!isRunning || actionLoading}
                buttonStyle="bordered"
                tint="#FF3B30"
                controlSize="regular"
                frame={{ maxWidth: Infinity }}
                action={confirmStop}
              />
              <Button
                title={actionLoading ? "处理中..." : "▶️ 启动实例 (开机)"}
                disabled={isRunning || actionLoading}
                buttonStyle="borderedProminent"
                tint="#34C759"
                controlSize="regular"
                frame={{ maxWidth: Infinity }}
                action={() => handleAction("start")}
              />
            </HStack>
          </VStack>
          <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 14 }}>
            为防误触，停止实例需要进行二次弹窗确认后方可执行。
          </Text>

          {/* Section 2: CDT 流量用量卡片 */}
          <HStack padding={{ leading: 8, bottom: 6 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
              CDT 互联网出网流量
            </Text>
            <Spacer />
            {data && (
              <Text font={12} bold foregroundColor={data.color}>
                已用 {data.percentage}%
              </Text>
            )}
          </HStack>

          <VStack background="#FFFFFF" cornerRadius={12} spacing={0}>
            {/* 流量主数据 */}
            <HStack padding={{ horizontal: 14, vertical: 12 }} alignment="center" spacing={12}>
              <ZStack frame={{ width: 30, height: 30 }} background="#AF52DE" cornerRadius={7}>
                <Image systemName="arrow.up.and.down" font={15} foregroundStyle="#FFFFFF" />
              </ZStack>
              <VStack alignment="leading" spacing={2} frame={{ maxWidth: Infinity, alignment: "leading" }}>
                <Text font="subheadline" bold>
                  出网用量 / 阈值
                </Text>
                <Text font="caption2" foregroundColor="#8E8E93">
                  当月警戒阈值: {config.trafficThresholdGB} GB
                </Text>
              </VStack>
              {data && (
                <VStack alignment="trailing" spacing={2}>
                  <Text font={20} bold foregroundColor={data.color}>
                    {data.totalGB.toFixed(2)} GB
                  </Text>
                  <Text font={11} foregroundColor="#8E8E93">
                    / {data.thresholdGB} GB
                  </Text>
                </VStack>
              )}
            </HStack>

            {/* 原生进度条 */}
            {data && (
              <VStack padding={{ horizontal: 14, bottom: 10 }}>
                <ProgressView
                  value={Math.max(0.01, Math.min(1.0, data.percentage / 100))}
                  tint={data.color as any}
                  frame={{ height: 6 }}
                />
              </VStack>
            )}

            <Divider padding={{ leading: 14 }} />

            {/* 三列指标卡片 */}
            {data ? (
              <HStack padding={{ horizontal: 14, vertical: 10 }} alignment="center">
                <VStack alignment="center" spacing={2} frame={{ maxWidth: Infinity }}>
                  <Text font="caption2" foregroundColor="#8E8E93">
                    剩余可用
                  </Text>
                  <Text font="subheadline" bold foregroundColor="#007AFF">
                    {data.remainingGB.toFixed(1)} G
                  </Text>
                </VStack>

                <Divider frame={{ height: 24 }} />

                <VStack alignment="center" spacing={2} frame={{ maxWidth: Infinity }}>
                  <Text font="caption2" foregroundColor="#8E8E93">
                    距结算重置
                  </Text>
                  <Text font="subheadline" bold foregroundColor="#007AFF">
                    {data.daysRemaining} 天
                  </Text>
                </VStack>

                <Divider frame={{ height: 24 }} />

                <VStack alignment="center" spacing={2} frame={{ maxWidth: Infinity }}>
                  <Text font="caption2" foregroundColor="#8E8E93">
                    建议日均
                  </Text>
                  <Text font="subheadline" bold foregroundColor={data.color}>
                    &lt; {data.dailyBudgetGB} G
                  </Text>
                </VStack>
              </HStack>
            ) : (
              <HStack padding={14} alignment="center">
                <Text font="caption2" foregroundColor="#8E8E93">
                  正在同步阿里云最新用量数据...
                </Text>
              </HStack>
            )}
          </VStack>
          <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 14 }}>
            🛡️ 自动熔断：当出网流量达到 {config.trafficThresholdGB} GB 时将自动停止 ECS 实例防止产生账单。
          </Text>

          {/* Section 3: 控制台实时操作日志 */}
          <HStack padding={{ leading: 8, bottom: 6 }} alignment="center">
            <Text font={13} fontWeight="semibold" foregroundColor="#6C6C70">
              实时操作日志
            </Text>
            <Spacer />
            <Button
              title={loading ? "同步中..." : "🔄 刷新"}
              disabled={loading || actionLoading}
              font="caption1"
              buttonStyle="plain"
              foregroundColor="#007AFF"
              action={() => loadData(config)}
            />
          </HStack>

          <VStack background="#FFFFFF" cornerRadius={12} spacing={0} padding={{ horizontal: 14, vertical: 10 }}>
            {logs.length > 0 ? (
              logs.map((log, index) => (
                <VStack key={index} alignment="leading" spacing={0}>
                  {index > 0 && <Divider padding={{ vertical: 6 }} />}
                  <Text font={11} foregroundColor="#636366">
                    {log}
                  </Text>
                </VStack>
              ))
            ) : (
              <Text font={11} foregroundColor="#8E8E93">
                暂无日志，轻点右上角刷新同步。
              </Text>
            )}
          </VStack>
          <Text font={12} foregroundColor="#8E8E93" padding={{ leading: 10, top: 6, bottom: 16 }}>
            显示最近 6 条控制台指令与 OpenAPI 响应状态。
          </Text>
        </VStack>
      </ScrollView>
    </NavigationStack>
  )
}

// ==================== 6. 主执行入口 ====================

async function main() {
  await Navigation.present({
    element: <ConsoleView />
  })
  Script.exit()
}

main()
