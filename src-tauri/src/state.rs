//! 会话状态（CONTRACT §5 state.rs；设计 T2.1）。
//!
//! 全局唯一状态 `AppState = Mutex<Option<Session>>`；None = 锁定态。
//! 密钥只活在这里：锁定 = 置 None 即 Drop 清零（Key32 为 Zeroizing）。
//! 本文件不依赖 tauri（M1 核心可单独编译）；commands 层在其上薄封装。

use std::path::PathBuf;
use std::sync::Mutex;

use rusqlite::Connection;

use crate::crypto::secret::Key32;

/// 会话模式：本地（文件容器） / 联网（远程服务器 + 内存库）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionMode {
    Local,
    Remote,
}

impl SessionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionMode::Local => "local",
            SessionMode::Remote => "remote",
        }
    }
}

/// 一条待处理同步冲突（sync_now 检测到、sync_conflict_resolve 消费）。
/// 存服务器侧完整行快照：选择\"以服务器为准/复制为新条目\"时无需再拉网络。
#[derive(Debug, Clone)]
pub struct RemoteConflict {
    pub id: String,
    pub server_kind: u8,
    pub server_salt: Vec<u8>,
    pub server_blob: Vec<u8>,
    pub server_created_at: u64,
    pub server_updated_at: u64,
    pub server_rev: String,
    pub local_updated_at: u64,
}

/// 服务器地址配置（只存连接信息，不含任何凭据；凭据只在内存/会话内）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCfg {
    pub address: String,
    pub port: u16,
    pub https: bool,
}

impl ServerCfg {
    /// 形如 http(s)://address:port。
    pub fn base_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{}://{}:{}", scheme, self.address, self.port)
    }
}

/// 解锁后的会话。
pub struct Session {
    /// 模式。
    pub mode: SessionMode,
    /// 本地模式下的容器文件路径（联网模式为 None，除非启用本地缓存）。
    pub vault_path: Option<PathBuf>,
    /// 联网模式的服务器配置。
    pub server_cfg: Option<ServerCfg>,
    /// 联网模式 JWT（仅存内存，锁定即弃）。
    pub token: Option<String>,
    /// 主密钥 MK（解锁时解出，终身不变；改密仅重包）。
    pub mk: Key32,
    /// 数据密钥 DK = HKDF(MK)。
    pub dk: Key32,
    /// 解锁后的内存库（明文结构 + 密文条目）。
    pub db: Connection,
    /// 是否有未保存变更（保存 = flush 本地 / sync 联网）。
    pub dirty: bool,
    /// 待用户裁决的同步冲突（仅远程模式非空；CONTRACT §3 sync_conflict_resolve）。
    pub pending_conflicts: Vec<RemoteConflict>,
    /// 最后活动时间（自动锁定判定，M4 完善）。
    pub last_activity_ms: u64,
}

/// 全局状态：None = 锁定。
pub struct AppState(pub Mutex<Option<Session>>);

impl AppState {
    pub fn new() -> Self {
        AppState(Mutex::new(None))
    }

    /// 便捷加锁入口（调用方注意：guard 不要跨 await 持有）。
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Option<Session>> {
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
