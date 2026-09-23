/**
 * 阿里云小组件交互意图 (iOS 17+ 交互式组件操作)
 * 必须置于 app_intents.tsx 中，由 AppIntentManager 注册
 */
import { AppIntentManager, AppIntentProtocol, Widget } from "scripting"

/** 意图 1：静默刷新小组件数据 */
export const RefreshTrafficIntent = AppIntentManager.register({
  name: "RefreshTrafficIntent",
  protocol: AppIntentProtocol.AppIntent,
  perform: async () => {
    try {
      if (typeof Widget !== "undefined" && Widget.reloadAllTimelines) {
        Widget.reloadAllTimelines()
      }
    } catch (e) {
      console.error("RefreshTrafficIntent 失败:", e)
    }
  }
})
