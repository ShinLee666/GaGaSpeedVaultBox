//! 对外统一错误类型与错误码（CONTRACT §4）。
//!
//! 前端收到的永远是 `VaultErrorDto { code, message }`（serde JSON）。
//! `code` 取值全集：wrong_password / answer_wrong / corrupt / not_found /
//! already_exists / not_unlocked / weak_password / conflict / unreachable /
//! tls_error / unauthorized / bad_request / internal。
//!
//! 密码学底层错误（CryptoError）与 IO/SQLite/JSON 错误在功能入口处
//! 被翻译为上述语义（例如：解 wrapped_MK 认证失败 -> WrongPassword，
//! 解 body 认证失败 -> Corrupt），翻译逻辑集中在 vault/container.rs。

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// VaultBox 领域错误（本地 + 联网两模式共用）。
///
/// 本文件被 desktop/src-tauri 复用后追加了 `impl Serialize for VaultError`
/// （见文件尾部）：tauri command 直接返回 `Result<T, VaultError>`，
/// 序列化为 CONTRACT §4 的 `{code, message}` 抛给前端。
#[derive(Debug, Error)]
pub enum VaultError {
    /// 密码错误（解 wrapped_MK 认证失败）。不区分"文件损坏/密码错误"防探测。
    #[error("密码错误")]
    WrongPassword,
    /// 保护问题答案错误。
    #[error("保护问题答案错误")]
    AnswerWrong,
    /// 容器/数据库损坏、被篡改或版本不受支持。
    #[error("文件损坏或版本不受支持，可尝试从备份恢复")]
    Corrupt,
    /// 条目或文件不存在。
    #[error("不存在")]
    NotFound,
    /// 目标已存在（如目录下已有 .vault）。
    #[error("已存在")]
    AlreadyExists,
    /// 需要先解锁。
    #[error("保险箱未解锁")]
    NotUnlocked,
    /// 密码强度不足（带原因）。
    #[error("密码强度不足：{0}")]
    WeakPassword(String),
    /// 同步冲突（带条目 id）。
    #[error("同步冲突：{0}")]
    Conflict(String),
    /// 服务器不可达 / 网络超时。
    #[error("无法连接服务器，请检查地址与网络")]
    Unreachable,
    /// TLS / 证书错误。
    #[error("TLS 证书错误")]
    TlsError,
    /// 未授权（JWT 无效或过期）。
    #[error("登录已过期，请重新登录")]
    Unauthorized,
    /// 请求参数不合法（带原因）。
    #[error("参数不合法：{0}")]
    BadRequest(String),
    /// 内部错误（IO/SQLite/JSON/底层密码学等，带详情，仅日志，不上 UI 详情）。
    #[error("内部错误：{0}")]
    Internal(String),
    /// 底层 IO 错误（自动包装为 Internal / NotFound）。
    #[error("io 错误：{0}")]
    Io(#[from] std::io::Error),
    /// 底层 SQLite 错误（自动包装为 Internal）。
    #[error("sqlite 错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    /// 底层 JSON 错误（自动包装为 Internal）。
    #[error("json 错误：{0}")]
    Json(#[from] serde_json::Error),
    /// 底层密码学错误（自动包装为 Internal；认证类失败已在上层翻译）。
    #[error("crypto 错误：{0}")]
    Crypto(#[from] crate::crypto::CryptoError),
}

impl VaultError {
    /// 错误码全集映射（CONTRACT §4）。前端按 code 映射中文文案。
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::WrongPassword => "wrong_password",
            VaultError::AnswerWrong => "answer_wrong",
            VaultError::Corrupt => "corrupt",
            VaultError::NotFound => "not_found",
            VaultError::AlreadyExists => "already_exists",
            VaultError::NotUnlocked => "not_unlocked",
            VaultError::WeakPassword(_) => "weak_password",
            VaultError::Conflict(_) => "conflict",
            VaultError::Unreachable => "unreachable",
            VaultError::TlsError => "tls_error",
            VaultError::Unauthorized => "unauthorized",
            VaultError::BadRequest(_) => "bad_request",
            // 底层包装错误一律归 internal（对外不泄露细节）
            VaultError::Internal(_)
            | VaultError::Io(_)
            | VaultError::Sqlite(_)
            | VaultError::Json(_)
            | VaultError::Crypto(_) => "internal",
        }
    }
}

/// 序列化给前端的错误体（CONTRACT §4：`{code, message}`）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultErrorDto {
    pub code: String,
    pub message: String,
}

impl From<&VaultError> for VaultErrorDto {
    fn from(e: &VaultError) -> Self {
        VaultErrorDto {
            code: e.code().to_string(),
            message: e.to_string(),
        }
    }
}

impl From<VaultError> for VaultErrorDto {
    fn from(e: VaultError) -> Self {
        VaultErrorDto::from(&e)
    }
}

impl std::fmt::Display for VaultErrorDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// tauri command 错误通道：`Result<T, VaultError>` 的 Err 序列化为
/// CONTRACT §4 的 `{code, message}`（前端 useVault.extractCode 直接可读）。
/// 自定义实现而非 derive：只暴露 code/message，绝不泄露底层细节。
impl Serialize for VaultError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        VaultErrorDto::from(self).serialize(serializer)
    }
}
