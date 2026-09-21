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
  VStack,
  HStack,
  ZStack,
  Text,
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
    <VStack alignment="leading" spacing={4}>
      <Text font="headline" bold foregroundColor="#FF9F0A">
        ⚙️ 待配置
      </Text>
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

function MediumWidget({ data }: { data: MonitorData }) {
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
          距重置:
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
  const [ak, setAk] = useState(currentConfig.accessKeyId)
  const [sk, setSk] = useState(currentConfig.accessKeySecret)
  const [region, setRegion] = useState(currentConfig.regionId || "cn-hongkong")
  const [ecsId, setEcsId] = useState(currentConfig.ecsInstanceId)
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || 180))
  const [autoStop, setAutoStop] = useState(currentConfig.autoStopOnExceed)
  const [errNotice, setErrNotice] = useState<string | null>(null)

  const handleSave = () => {
    if (!ak.trim() || !sk.trim() || !ecsId.trim()) {
      setErrNotice("请填写完整的 AccessKey ID、Secret 与 ECS 实例 ID！")
      return
    }
    const newCfg: AppConfig = {
      accessKeyId: ak.trim(),
      accessKeySecret: sk.trim(),
      regionId: region.trim() || "cn-hongkong",
      ecsInstanceId: ecsId.trim(),
      trafficThresholdGB: parseFloat(threshold) || 180,
      resetDayOfMonth: 1,
      autoStopOnExceed: autoStop
    }
    saveConfigToStorage(newCfg)
    onSave(newCfg)
  }

  return (
    <VStack alignment="leading" spacing={16} padding={16}>
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
        凭据保存在本地 Scripting Storage 中，安全且永不上云。
      </Text>

      {errNotice && (
        <HStack padding={10} background="rgba(255, 69, 58, 0.12)" cornerRadius={8}>
          <Text font="caption2" foregroundColor="#FF453A">
            ⚠️ {errNotice}
          </Text>
        </HStack>
      )}

      <VStack
        alignment="leading"
        spacing={12}
        padding={14}
        background="rgba(142, 142, 147, 0.08)"
        cornerRadius={12}
      >
        <VStack alignment="leading" spacing={4}>
          <Text font="caption2" bold foregroundColor="#8E8E93">
            AccessKey ID
          </Text>
          <TextField
            title="LTAIxxxxxxxxxxxx"
            value={ak}
            autocorrectionDisabled
            textInputAutocapitalization="never"
            onSubmit={() => {}}
          />
        </VStack>

        <Divider />

        <VStack alignment="leading" spacing={4}>
          <Text font="caption2" bold foregroundColor="#8E8E93">
            AccessKey Secret
          </Text>
          <TextField
            title="xxxxxxxxxxxxxxxxxxxxxxxxxx"
            value={sk}
            autocorrectionDisabled
            textInputAutocapitalization="never"
            onSubmit={() => {}}
          />
        </VStack>

        <Divider />

        <VStack alignment="leading" spacing={4}>
          <Text font="caption2" bold foregroundColor="#8E8E93">
            ECS 地域 (Region ID)
          </Text>
          <TextField
            title="cn-hongkong"
            value={region}
            autocorrectionDisabled
            textInputAutocapitalization="never"
            onSubmit={() => {}}
          />
        </VStack>

        <Divider />

        <VStack alignment="leading" spacing={4}>
          <Text font="caption2" bold foregroundColor="#8E8E93">
            ECS 实例 ID
          </Text>
          <TextField
            title="i-j6cxxxxxxxxxxxx"
            value={ecsId}
            autocorrectionDisabled
            textInputAutocapitalization="never"
            onSubmit={() => {}}
          />
        </VStack>

        <Divider />

        <VStack alignment="leading" spacing={4}>
          <Text font="caption2" bold foregroundColor="#8E8E93">
            CDT 流量警戒阈值 (GB)
          </Text>
          <TextField
            title="180"
            value={threshold}
            keyboardType="numberPad"
            onSubmit={() => {}}
          />
        </VStack>

        <Divider />

        <HStack>
          <VStack alignment="leading" spacing={2}>
            <Text font="subheadline">超额自动关机防扣费</Text>
            <Text font="caption2" foregroundColor="#8E8E93">
              当达到阈值时自动停止 ECS
            </Text>
          </VStack>
          <Spacer />
          <Toggle
            isOn={autoStop}
            onToggle={() => setAutoStop(!autoStop)}
          />
        </HStack>
      </VStack>

      <Button
        title="💾 保存配置并进入控制台"
        buttonStyle="borderedProminent"
        controlSize="large"
        action={handleSave}
      />
    </VStack>
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
