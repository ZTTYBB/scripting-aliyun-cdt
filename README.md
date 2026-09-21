# 阿里云 CDT 流量监控与 ECS 智控小组件 (Scripting iOS)

专为 iOS 平台 **Scripting** 应用打造的阿里云 CDT 流量与 ECS 实例智控系统，采用原生 TSX 语法构建，完美适配 iOS 16/17/18 桌面小组件与 App 内控制台。

---

## 🚀 一键安装 (快速导入)

在已安装 **Scripting** 的 iPhone / iPad 上，点击下方链接即可自动跳转 Scripting 并完成安装：

👉 **[📥 点击一键导入到 Scripting](https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fraw.githubusercontent.com%2FZTTYBB%2Fscripting-aliyun-cdt%2Fmain%2FAliyunCDT.scripting%22%5D)**

> 💡 **原理说明**：Scripting 官方的一键导入协议 (`https://scripting.fun/import_scripts?urls=...`) 依赖打包好的 `.scripting` 格式包（内含 `script.json`、`index.tsx`、`widget.tsx` 等入口配置）。本仓库已生成并发布标准的 `AliyunCDT.scripting` 安装包。

---

## 🌟 核心特性

- **🔒 零硬编码 & 隐私安全**：代码中不包含任何个人密钥，首次打开脚本自动弹出配置面板，凭据仅存储在用户 iPhone 本地 `Storage` 中，绝不上云。
- **📊 实时 CDT 公网出网流量监控**：聚合阿里云 CDT 计费账单，动态三色进度条（绿 / 橙 / 红），剩余流量精准推算，显示结算日倒计时与日均安全额度。
- **🖥️ ECS 远程开机与关机**：支持在控制台上一键启停 ECS，实时查看实例运行状态与公网 IP。
- **🛡️ 自动熔断防扣费**：达到设定阈值（默认 180 GB）自动执行关机保护。
- **📱 桌面小组件支持**：支持小号（Small）、中号（Medium）与锁屏（Lock Screen）小组件。

---

## 📲 安装与使用方法

### 方式 1：一键导入（最推荐）

1. 在手机 Safari 中打开本仓库，点击上方的 **[📥 点击一键导入到 Scripting](https://scripting.fun/import_scripts?urls=%5B%22https%3A%2F%2Fraw.githubusercontent.com%2FZTTYBB%2Fscripting-aliyun-cdt%2Fmain%2FAliyunCDT.scripting%22%5D)** 链接；
2. 系统将自动唤起 **Scripting** App 并提示导入；
3. 点击确认导入后，在脚本列表中点开 **AliyunCDT**；
4. 首次运行会自动弹出配置面板，填入您的阿里云：
   - **AccessKey ID**
   - **AccessKey Secret**
   - **地域 ID**（如 `cn-hongkong`）
   - **ECS 实例 ID**（如 `i-xxxxxxxxx`）
   - **流量阈值 (GB)**（默认 `180`）
5. 点击“保存配置”，即可立即进入控制台并同步生效到小组件！

### 方式 2：单文件直接复制

1. 复制 [`AliyunCDT_AllInOne.tsx`](./AliyunCDT_AllInOne.tsx) 的全部代码；
2. 打开 iPhone 上的 **Scripting** App，点击右上角新建脚本；
3. 粘贴代码并保存，点击运行即可。

---

## 🔒 阿里云 RAM 权限配置建议（最小权限原则）

在阿里云 RAM 控制台为子用户分配如下最小权限：

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
    }
  ]
}
```
