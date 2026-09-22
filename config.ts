/**
 * 阿里云 CDT 流量监控与 ECS 智控配置管理模块
 * 支持通过 Scripting Storage 本地持久化存储，无需硬编码凭据
 */
import { Storage } from "scripting"

export const APP_VERSION = "1.4.3"

export interface AppConfig {
  accessKeyId: string
  accessKeySecret: string
  regionId: string
  ecsInstanceId: string
  trafficThresholdGB: number
  resetDayOfMonth: number
  autoStopOnExceed: boolean
}

export const DEFAULT_CONFIG: AppConfig = {
  accessKeyId: "",
  accessKeySecret: "",
  regionId: "cn-hongkong",
  ecsInstanceId: "",
  trafficThresholdGB: 180,
  resetDayOfMonth: 1,
  autoStopOnExceed: true
}

export const STORAGE_KEY = "aliyun_cdt_monitor_config"

/** 从本地 Storage 读取配置 */
export function loadConfig(): AppConfig {
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

/** 将配置保存到本地 Storage */
export function saveConfig(cfg: AppConfig): void {
  try {
    if (typeof Storage !== "undefined" && Storage?.set) {
      Storage.set(STORAGE_KEY, JSON.stringify(cfg))
    }
  } catch (e) {
    console.error("保存本地配置失败:", e)
  }
}

/** 检查是否已完成基本配置 */
export function isConfigured(cfg: AppConfig): boolean {
  return (
    Boolean(cfg.accessKeyId?.trim()) &&
    Boolean(cfg.accessKeySecret?.trim()) &&
    Boolean(cfg.ecsInstanceId?.trim())
  )
}
