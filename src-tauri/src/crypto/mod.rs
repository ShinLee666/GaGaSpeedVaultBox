//! 密码学模块（纯算法，不依赖 IO / GUI）。
//!
//! 子模块：secret（敏感内存类型与随机源）、kdf（Argon2id）、
//! aead（AES-256-GCM 封装）、derive（HKDF-SHA256 派生）、error。
//! 依赖方向：`crypto` 不反向依赖 `vault` / `db`。

pub mod aead;
pub mod derive;
pub mod error;
pub mod kdf;
pub mod secret;

pub use error::CryptoError;
pub use secret::{fill_random, random_key32, Key32, SecretBytes};
