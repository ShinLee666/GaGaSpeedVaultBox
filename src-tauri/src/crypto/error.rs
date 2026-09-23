//! 密码学底层错误（CONTRACT §5 crypto/error.rs）。
//!
//! 注意：这些错误不直接暴露给前端——vault 层会把"认证失败"翻译为
//! WrongPassword / Corrupt（见 crate::error::VaultError 与 vault/container.rs）。

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Argon2 参数不合法。
    #[error("kdf parameter invalid")]
    KdfParam,
    /// KDF 计算失败。
    #[error("kdf computation failed")]
    KdfFailed,
    /// 解密失败（认证失败 / 密码错误 / 密文被篡改，统一归类）。
    #[error("decryption failed (auth)")]
    DecryptFailed,
    /// 加密失败。
    #[error("encryption failed")]
    EncryptFailed,
    /// 输入长度不合法（过短等）。
    #[error("bad blob length")]
    BadLength,
    /// 版本 / 算法标识不支持。
    #[error("unsupported version")]
    UnsupportedVersion,
    /// 容器头部结构损坏。
    #[error("corrupt header")]
    CorruptHeader,
}
