/**
 * 阿里云小组件交互意图 (iOS 17+ 交互式组件操作)
 * 必须置于 app_intents.tsx 中，由 AppIntentManager 注册
 */
import { AppIntentManager, AppIntentProtocol, Widget } from "scripting"
import { AliyunService } from "./aliyun"
import { loadConfig } from "./config"

const aliyun = new AliyunService(loadConfig())

/** 意图 1：静默刷新小组件数据 */
export const RefreshTrafficIntent = AppIntentManager.register({
  name: "RefreshTrafficIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    try {
      await aliyun.checkAndEnforceThreshold()
    } catch (e) {
      console.error("RefreshTrafficIntent 失败:", e)
    }
  }
})

/** 意图 2：在小组件上一键启动 ECS */
export const StartECSIntent = AppIntentManager.register({
  name: "StartECSIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    try {
      await aliyun.startECS()
    } catch (e) {
      console.error("StartECSIntent 失败:", e)
    }
  }
})

/** 意图 3：在小组件上一键停止 ECS */
export const StopECSIntent = AppIntentManager.register({
  name: "StopECSIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    try {
      await aliyun.stopECS()
    } catch (e) {
      console.error("StopECSIntent 失败:", e)
    }
  }
})
