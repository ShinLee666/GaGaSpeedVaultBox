# VaultBox 隐私政策

**生效日期：2026 年 9 月 23 日**
**最近更新：2026 年 9 月 23 日**

VaultBox（"本应用"）是一款开源的本地优先加密保险箱。本政策适用于通过 GitHub 及各发布渠道分发的 VaultBox 各版本（包括纯本地版本与支持自建服务器同步的完整版），说明本应用如何对待您的数据。

**一句话概括：您的秘密只属于您。本应用不收集、不上传、不出售任何个人数据；所有保险箱内容均在您的设备上加密存储，开发者（以及任何第三方）在任何时候都无法读取。**

---

## 1. 我们收集哪些信息

**我们不收集任何个人信息。**

- 本应用没有账户体系（联网功能由您自建的服务器提供，与本项目开发者无关）。
- 本应用不嵌入任何统计分析、广告 SDK、崩溃上报或行为追踪组件。
- 本应用不会读取与您使用无关的设备文件、通讯录、位置、相册等信息。

## 2. 数据如何存储（本地优先，端到端加密）

- 您的保险箱数据（账号条目、备注、恢复问题的答案等）**仅保存在您的设备本地**，使用 **AES-256-GCM** 加密；加密密钥由您的主密码通过 **Argon2id** 密钥派生算法生成。
- 主密码与派生密钥**永远不会离开您的设备**，不会以任何形式被上传或存储。开发者无法重置、无法找回、无法读取您的密码和保险箱内容；主密码丢失且未设置恢复问题时，数据将不可恢复。
- 剪贴板：仅在您**主动点击"复制"**时，将您选中的内容写入系统剪贴板；本应用不会读取或监控剪贴板中的其他内容。

## 3. 纯本地版本

- 纯本地版本**不包含任何联网代码**，应用运行期间不会发起任何网络请求，所有数据 100% 保留在设备上。
- 卸载应用将删除设备上的全部本地保险箱数据（密文）。删除前请确保您不再需要这些数据，或已通过其他方式备份。

## 4. 完整版（自建服务器同步）

- 完整版提供**可选的**联网同步功能，仅连接到**您自行配置的服务器地址**。
- 同步过程中传输的数据为**密文**（端到端加密后的内容），服务器与任何中间方均无法解密。
- 该服务器由您或您信任的一方运营，其数据实践受该服务器运营方的政策约束，与本项目开发者无关。您可随时在应用内停用同步并注销。

## 5. 第三方组件

- 本应用在 Windows 上使用 Microsoft **WebView2** 运行时渲染界面，其对设备数据的使用受 [Microsoft 隐私条款](https://privacy.microsoft.com/) 约束。
- 除此之外，本应用不包含任何第三方服务组件。

## 6. 数据共享与披露

我们不会出售、出租、共享或向任何第三方披露您的数据——因为数据（包括密文）从未经过我们的服务器，我们没有任何可供披露的数据。

## 7. 数据安全

- 加密算法：AES-256-GCM（认证加密）、Argon2id（抗硬件暴力破解的密钥派生）。
- 密钥管理：主密钥仅存在于运行时内存，应用锁定后清除；不在磁盘、注册表或任何持久化位置保存明文密钥。
- 请您妥善保管主密码，并为设备启用系统级安全措施（如操作系统登录密码）。

## 8. 儿童隐私

本应用不面向 13 岁以下儿童，亦不会收集任何年龄用户的个人信息。

## 9. 政策更新

本政策更新后将在本页面公布新版本及生效日期。政策变更不会影响既有数据的存储方式。

## 10. 联系我们

如对本政策或数据处理方式有任何疑问，请在 GitHub 仓库提交 Issue：

- 项目仓库：https://github.com/ShinLee666/GaGaSpeedVaultBox

---

# VaultBox Privacy Policy (English)

**Effective date: September 23, 2026**

VaultBox ("the App") is an open-source, local-first encrypted vault. This policy applies to all editions distributed via GitHub and other channels, including the local-only edition and the full edition (self-hosted server sync).

**In short: your secrets belong only to you. The App collects, uploads, and sells no personal data. All vault contents are encrypted on your device, and no one — including the developer — can ever read them.**

## 1. What We Collect

**We do not collect any personal information.** The App has no account system of its own, contains no analytics, advertising, crash-reporting, or tracking SDKs, and does not access files, contacts, location, or photos unrelated to your use.

## 2. How Your Data Is Stored

- Vault data is stored **only on your device**, encrypted with **AES-256-GCM**; the key is derived from your master password via **Argon2id**.
- Your master password and derived keys **never leave your device**. No one can reset, recover, or read your password or vault contents. If the master password is lost and no recovery question was set, the data is unrecoverable.
- Clipboard: the App writes to the system clipboard **only when you explicitly tap "Copy"** on an item; it never reads or monitors clipboard content otherwise.

## 3. Local-Only Edition

The local-only edition contains **no networking code at all** — the App makes no network requests, and all data remains 100% on your device. Uninstalling the App deletes all local vault data (ciphertext).

## 4. Full Edition (Self-Hosted Sync)

- Sync is **optional** and connects only to a **server address you configure yourself**.
- Data in transit is **ciphertext** (end-to-end encrypted); neither the server nor any intermediary can decrypt it.
- That server is operated by you or a party you trust and is subject to that operator's own policies. You can disable sync and sign out at any time.

## 5. Third-Party Components

The App uses Microsoft's **WebView2** runtime on Windows, which is governed by the [Microsoft Privacy Statement](https://privacy.microsoft.com/). The App contains no other third-party service components.

## 6. Data Sharing and Disclosure

We do not sell, rent, share, or disclose your data to any third party — your data (including ciphertext) never passes through our servers, so we hold nothing to disclose.

## 7. Data Security

AES-256-GCM authenticated encryption; Argon2id key derivation; the master key exists only in runtime memory and is cleared when the vault is locked. Please keep your master password safe and use OS-level device protection.

## 8. Children's Privacy

The App is not directed at children under 13 and collects no personal information from users of any age.

## 9. Changes to This Policy

Updates are posted on this page with a new effective date. Changes do not alter how existing data is stored.

## 10. Contact Us

For questions about this policy, please open an issue on GitHub:

- Repository: https://github.com/ShinLee666/GaGaSpeedVaultBox
