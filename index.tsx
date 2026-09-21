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
  VStack,
  HStack,
  ZStack,
  Text,
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
  const [ak, setAk] = useState(currentConfig.accessKeyId)
  const [sk, setSk] = useState(currentConfig.accessKeySecret)
  const [region, setRegion] = useState(currentConfig.regionId || "cn-hongkong")
  const [ecsId, setEcsId] = useState(currentConfig.ecsInstanceId)
  const [threshold, setThreshold] = useState(String(currentConfig.trafficThresholdGB || 180))
  const [autoStop, setAutoStop] = useState(currentConfig.autoStopOnExceed)
  const [errorNotice, setErrorNotice] = useState<string | null>(null)

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
        所有凭据仅保存在您手机本机的 Scripting 隔离存储空间中，绝不上云或外泄。
      </Text>

      {errorNotice && (
        <HStack padding={10} background="rgba(255, 69, 58, 0.12)" cornerRadius={8}>
          <Text font="caption2" foregroundColor="#FF453A">
            ⚠️ {errorNotice}
          </Text>
        </HStack>
      )}

      {/* 表单项 */}
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
            ECS 所在地域 (Region ID)
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
              当达到阈值时自动执行 StopInstance
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

// ==================== 5. 控制台仪表盘主视图 ====================

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
    setLogs(prev => [`[${time}] ${msg}`, ...prev.slice(0, 9)])
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
        appendLog(`获取成功: CDT流量 ${res.totalGB} GB (${res.percentage}%)`)
        appendLog(`ECS 实例状态: ${res.ecsStatus} ${res.publicIp ? `(${res.publicIp})` : ""}`)
      } catch (err: any) {
        const msg = err?.message || "网络请求失败，请检查凭据或网络"
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

  // 2. 主控制台展示
  return (
    <NavigationStack>
      <VStack
        alignment="leading"
        spacing={16}
        padding={16}
        navigationTitle="阿里云 CDT & ECS 智控台"
      >
        {/* 顶部状态与设置入口 */}
        <HStack>
          <Text font="headline" bold>
            🖥️ 实例状态
          </Text>
          <Spacer />
          <Button
            title="⚙️ 设置"
            font="footnote"
            buttonStyle="bordered"
            action={() => setShowSettings(true)}
          />
        </HStack>

        {errorMessage && (
          <HStack padding={12} background="rgba(255, 69, 58, 0.12)" cornerRadius={10}>
            <Text font="footnote" foregroundColor="#FF453A">
              ⚠️ {errorMessage}
            </Text>
          </HStack>
        )}

        {/* ECS 卡片 */}
        <VStack
          alignment="leading"
          padding={16}
          background="rgba(142, 142, 147, 0.08)"
          cornerRadius={14}
          spacing={12}
        >
          <HStack>
            <HStack spacing={6}>
              <Text font="caption1">{isRunning ? "🟢" : "🔴"}</Text>
              <Text
                font="subheadline"
                bold
                foregroundColor={isRunning ? "#30D158" : "#FF453A"}
              >
                ECS {isRunning ? "运行中" : data?.ecsStatus === "Stopped" ? "已停止" : data?.ecsStatus || "加载中"}
              </Text>
            </HStack>
            <Spacer />
            <Text font="caption2" foregroundColor="#8E8E93">
              {config.regionId}
            </Text>
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
              title="🔴 停止实例 (关机)"
              disabled={!isRunning || actionLoading}
              buttonStyle="bordered"
              tint="#FF453A"
              action={() => handleAction("stop")}
            />
            <Button
              title="🟢 启动实例 (开机)"
              disabled={isRunning || actionLoading}
              buttonStyle="borderedProminent"
              tint="#30D158"
              action={() => handleAction("start")}
            />
          </HStack>
        </VStack>

        {/* CDT 流量卡片 */}
        <VStack
          alignment="leading"
          padding={16}
          background="rgba(142, 142, 147, 0.08)"
          cornerRadius={14}
          spacing={12}
        >
          <HStack>
            <Text font="headline" bold>
              📊 CDT 互联网出网流量
            </Text>
            <Spacer />
            {data && (
              <Text font="footnote" bold foregroundColor={data.color}>
                已用 {data.percentage}%
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
                  距结算重置: {data.daysRemaining} 天
                </Text>
                <Spacer />
                <Text font="caption2" foregroundColor="#8E8E93">
                  建议每日安全配额: &lt; {data.dailyBudgetGB} GB
                </Text>
              </HStack>
            </VStack>
          ) : (
            <Text font="subheadline" foregroundColor="#8E8E93">
              正在拉取实时数据...
            </Text>
          )}
        </VStack>

        {/* 运行日志 */}
        <VStack
          alignment="leading"
          padding={14}
          background="rgba(0, 0, 0, 0.04)"
          cornerRadius={12}
          spacing={6}
        >
          <HStack>
            <Text font="caption1" bold foregroundColor="#8E8E93">
              📋 控制台操作日志
            </Text>
            <Spacer />
            <Button
              title={loading ? "刷新中..." : "🔄 刷新"}
              disabled={loading || actionLoading}
              font="caption2"
              action={() => loadData(config)}
            />
          </HStack>
          {logs.map((log, index) => (
            <Text key={index} font="caption2" foregroundColor="#636366">
              {log}
            </Text>
          ))}
        </VStack>

        <Spacer />

        <HStack padding={{ bottom: 8 }} alignment="center">
          <Spacer />
          <Text font="caption2" foregroundColor="#8E8E93">
            🛡️ 自动熔断保护已开启 (≥ {config.trafficThresholdGB}GB 自动停止防扣费)
          </Text>
          <Spacer />
        </HStack>
      </VStack>
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
