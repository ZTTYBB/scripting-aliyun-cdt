# 阿里云 CDT 流量监控与 ECS 智控小组件 (Scripting iOS)

专为 iOS 平台 **Scripting** 应用打造的阿里云 CDT 流量与 ECS 实例智控系统，采用原生 TSX 语法构建，完美适配 iOS 16/17/18 桌面小组件与 App 内控制台。

---

## 🌟 核心特性

- **🔒 零硬编码 & 隐私安全**：代码中不包含任何个人密钥，首次打开脚本自动弹出配置面板，凭据仅存储在用户 iPhone 本地 `Storage` 中，绝不上云。
- **📊 实时 CDT 公网出网流量监控**：聚合阿里云 CDT 计费账单，动态三色进度条（绿 / 橙 / 红），剩余流量精准推算，显示结算日倒计时与日均安全额度。
- **🖥️ ECS 远程开机与关机**：支持在控制台上一键启停 ECS，实时查看实例运行状态与公网 IP。
- **🛡️ 自动熔断防扣费**：达到设定阈值（默认 180 GB）自动执行关机保护。
- **📱 桌面小组件支持**：支持小号（Small）、中号（Medium）与锁屏（Lock Screen）小组件。

---

## 📲 安装与使用方法

### 方式 A：单文件直接导入（最快）

1. 复制 [`AliyunCDT_AllInOne.tsx`](./AliyunCDT_AllInOne.tsx) 的全部代码；
2. 打开 iPhone 上的 **Scripting** App，点击右上角新建脚本；
3. 粘贴代码并保存，点击运行；
4. 首次运行时会自动弹出设置面板，填入您的阿里云：
   - **AccessKey ID**
   - **AccessKey Secret**
   - **地域 ID**（如 `cn-hongkong`）
   - **ECS 实例 ID**（如 `i-xxxxxxxxx`）
   - **流量阈值 (GB)**（默认 `180`）
5. 点击“保存配置”，即可立即进入控制台并同步生效到小组件！

### 方式 B：作为项目文件夹导入

1. 将 `AliyunCDTMonitor` 文件夹导入至手机 Files 应用中的 `Scripting` 目录；
2. 文件夹包含：
   - `index.tsx`：App 内主控制台与设置面板；
   - `widget.tsx`：桌面小组件渲染逻辑；
   - `config.ts`：配置与 Storage 持久化管理；
   - `aliyun.ts`：HMAC-SHA1 签名与 POP API 客户端。

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
