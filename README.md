# 阿里云 CDT 免费流量监控与 ECS 财务对账看板 (Scripting iOS)

[![Version](https://img.shields.io/badge/version-1.6.0-blue.svg)](https://github.com/ZTTYBB/scripting-aliyun-cdt)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B-lightgrey.svg)](https://apps.apple.com/app/scripting/id1575361494)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

专为 iOS **Scripting** 打造的阿里云 CDT 流量监控、BSS 官方账单与 ECS 状态看板，采用原生 TypeScript + TSX 构建，支持 iOS 16+ 桌面全尺寸小组件与应用内只读控制台。

> 💡 **v1.6.0**：手机端只读取阿里云用量、账单与 ECS 状态；VPS 保活、夜间休眠和熔断策略保持独立运行。手机不连接 VPS，也不会对 ECS 执行开机、关机或重启。

---

## 🚀 一键安装 (快速导入)

在已安装 **Scripting** 的 iPhone / iPad 上，点击下方链接即可自动唤起 Scripting 完成安装：

👉 **[📥 点击一键导入到 Scripting](https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fraw.githubusercontent.com%2FZTTYBB%2Fscripting-aliyun-cdt%2Fmain%2FAliyunCDT.scripting%22%5D)**

> 💡 **原理说明**：本仓库预先生成并持续构建标准的 `AliyunCDT.scripting` 安装包，包含完整的 `script.json` 与模块化代码。

---

## 🌟 核心特性

- **🔒 零硬编码**：代码中无任何 AK/SK，首次打开自动弹出设置面板，支持**智能剪贴板识别提取**。凭据保存在 Scripting 本机 Storage；此项目未实现应用层加密，建议使用专用、最小权限的 RAM 凭据。
- **📊 CDT 用量看板**：阿里云免费额度按地域分池；公开规则为内地 20 GB、非内地 200 GB，并按账号规则共享。本项目汇总接口返回的流量后按单一 `200 GB` 本地参考值计算，不会推算各地域免费额度池的真实余量。
- **💰 BSS 账单查询**：读取阿里云账单接口返回的金额字段。月内数据约有 24 小时延迟且仅供参考，最终账单通常在次月 3 日 12:00 后可查；查询不可用时不会伪装成零费用。
- **📅 每日账单查询**：可查看最近 7 日 ECS 与 EIP 分类结果。每日明细同样受账单出账延迟影响，不保证是最终金额。
- **💳 账户余额看板**：展示阿里云接口返回的可用余额与状态；查询失败时不影响用量和账单区域展示。
- **🖥️ ECS 状态只读展示**：显示阿里云返回的实例状态；实例“已停止”不代表手机能够判断是谁或哪条策略停止了它。
- **📏 两条流量参考线**：默认 200 GB 月用量参考值与 195 GB VPS 熔断参考线均可在设置中修改。它们只用于本机界面计算和提醒，不代表账号完整免费额度余额，不会操作 ECS，也不会同步或校验 VPS 配置。
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
* **月用量参考值**：默认为 `200 GB`，仅用于本地计算；实际 CDT 免费额度受地域及阿里云账户规则影响。
* **VPS 熔断参考线**：默认为 `195 GB`，请按 VPS 脚本设置手动核对；仅用于手机界面告警，不会操作 ECS。

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
        "ecs:DescribeInstances"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "bss:DescribeAcccount",
        "bss:DescribeBillList",
        "bss:QueryAccountBill"
      ],
      "Resource": "*"
    }
  ]
}
```

> ⚠️ **注意**：账单总览、账户余额与日账单使用不同的 BSS 授权动作。若某项查询失败，请按阿里云对应 OpenAPI 文档核对该 API 的 RAM 授权动作；账单查询失败会显示为不可用，不会当作 ¥0。

---

## 🤝 与 VPS 自动化脚本分工

推荐搭配远端 VPS 定时脚本（参考 NodeSeek 经典方案）：
1. **VPS 后台脚本负责**：
   - VPS 脚本独立负责保活、定时运行/停止与流量熔断。手机项目不修改、不调用 VPS，也不代替它执行策略。
2. **手机端 Scripting 小组件负责**：
   - 随手在桌面查看 CDT 用量参考、可用余额与当前账单查询结果；
   - 实时查看阿里云当前返回的 ECS 状态。手机与 VPS 没有通讯链路，因此不会显示 VPS 脚本的运行状态或关机原因。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 开源。
