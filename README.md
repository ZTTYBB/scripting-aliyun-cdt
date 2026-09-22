# 阿里云 CDT 免费流量监控与 ECS 财务对账看板 (Scripting iOS)

[![Version](https://img.shields.io/badge/version-1.5.0-blue.svg)](https://github.com/ZTTYBB/scripting-aliyun-cdt)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-lightgrey.svg)](https://apps.apple.com/app/scripting/id1575361494)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

专为 iOS **Scripting** 打造的阿里云 CDT 免费公网流量监控、BSS 官方财务对账与 ECS 节省停机状态看板，采用原生 TypeScript + TSX 构建，支持 iOS 16+ 桌面全尺寸小组件与应用内交互式控制台。

> 💡 **v1.5.0 全新架构**：支持与远端 VPS 自动化运维脚本（定时保活、夜间休眠、紧急熔断）完美配合。手机端采用 **100% 纯只读数据看板** 模式，零后台风险操作，安全防误关。

---

## 🚀 一键安装 (快速导入)

在已安装 **Scripting** 的 iPhone / iPad 上，点击下方链接即可自动唤起 Scripting 完成安装：

👉 **[📥 点击一键导入到 Scripting](https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fraw.githubusercontent.com%2FZTTYBB%2Fscripting-aliyun-cdt%2Fmain%2FAliyunCDT.scripting%22%5D)**

> 💡 **原理说明**：本仓库预先生成并持续构建标准的 `AliyunCDT.scripting` 安装包，包含完整的 `script.json` 与模块化代码。

---

## 🌟 核心特性

- **🔒 零硬编码 & 隐私安全**：代码中无任何 AK/SK，首次打开自动弹出设置面板，支持**智能剪贴板一键识别提取**。所有凭据仅加密保存在用户 iPhone 本机 `Storage` 中，绝不上云。
- **📊 CDT 200GB 免费流量池实时追踪**：直观展示当月已用出网流量、剩余免费可用额度、重置倒计时与每日健康建议预算，远离超额扣费。
- **💰 抢占式折后真实账单（无猜测）**：直接接入阿里云 BSS OpenAPI 官方账单接口，优先提取 `PretaxAmount`（实际折后应付金额）。完美支持**抢占式竞价折扣、优惠券与抹零抵扣**，精准如实展示真实应付总额（如 ¥0.44）。
- **📅 每日账单深度钻取**：控制台支持轻点费用卡片弹出「最近 7 日账单明细」，实时获取官方单日折后真实支出（如 ECS ¥0.13/天、今日 ¥0.09），支持按 ECS 与 EIP 分类下钻。
- **💳 账户实时可用余额看板**：同步展示阿里云账户可用现金余额与财务健康状态，防止因欠费导致资源停机。
- **🌙 节省停机 (StopCharging) 智能联动**：
  - 自动识别实例的“节省停机”模式；
  - 当 VPS 脚本在夜间执行节省停机（计算资源 ¥0 计费）时，手机端小组件与控制台自动呈现 **`🌙 节省停机中 (休眠)`** 状态，安心省钱。
- **🤖 VPS 托管纯统计模式（手机 100% 纯只读）**：
  - 彻底剥离手机端后台的主动关机逻辑，所有保活、定时休眠与流量熔断由 VPS 后台独立负责；
  - 手机端作为纯粹的数据统计与对账看板，杜绝两端双重误关机冲突。
- **📱 全尺寸桌面小组件适配**：支持小号（Small）、中号（Medium）、大号（Large）与锁屏（Lock Screen）小组件，自带优雅的 Apple 质感发光环与状态指示。

---

## 📲 使用与配置步骤

### 1. 导入脚本
- **方式 A（最推荐）**：点击上方的 **[一键导入链接](https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fraw.githubusercontent.com%2FZTTYBB%2Fscripting-aliyun-cdt%2Fmain%2FAliyunCDT.scripting%22%5D)** 自动安装；
- **方式 B（单文件）**：直接复制 [`AliyunCDT_AllInOne.tsx`](./AliyunCDT_AllInOne.tsx) 全文粘贴到 Scripting 新建脚本中。

### 2. 填写配置
首次运行会自动弹出设置面板（支持复制包含密钥的文本点击**一键识别**自动填入）：
* **AccessKey ID / Secret**：阿里云 RAM 访问凭据。
* **地域 ID**：实例所在地域（如香港为 `cn-hongkong`）。
* **ECS 实例 ID**：需要监控的实例编号（如 `i-xxxxxxxx`）。
* **流量阈值**：默认为 `200`（对齐 CDT 全额免费上限）。
* **手机端自动关机**：建议保持**关闭**（交由 VPS 后台守护）。

---

## 🔒 阿里云 RAM 权限配置建议（最小权限原则）

为了脚本能够正常拉取 CDT 流量、ECS 状态、账户余额与折后账单，请在阿里云 RAM 访问控制台为子账号授予如下**最小必要权限策略**：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cdt:ListCdtInternetTraffic"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecs:DescribeInstances",
        "ecs:StartInstance",
        "ecs:StopInstance"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "bss:QueryAccountBalance",
        "bss:QueryBillOverview",
        "bss:QueryAccountBill"
      ],
      "Resource": "*"
    }
  ]
}
```

> ⚠️ **注意**：`bss:*` 权限用于查询账单总览、每日实际费用与账户现金余额。如果不授予，账单卡片将无法读取数据。

---

## 🤝 搭配 VPS 脚本实现“极致省钱 (月费 2~3 元)”

推荐搭配远端 VPS 定时脚本（参考 NodeSeek 经典方案）：
1. **VPS 后台脚本负责**：
   - 每天夜间 02:30 ~ 08:00 自动调用 `StopCharging`（节省停机）暂停 CPU/内存计费；
   - 每天早上 08:00 自动唤醒开机；
   - CDT 流量超过 195GB 时触发紧急熔断关机；
   - 每天 23:59 推送 Telegram 统计日报。
2. **手机端 Scripting 小组件负责**：
   - 随手在桌面查看剩余流量、可用余额、当月折后账单（¥0.44）；
   - 实时查看服务器是运行中还是夜间休眠状态；
   - 紧急情况下可手动控制开机/关机。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
