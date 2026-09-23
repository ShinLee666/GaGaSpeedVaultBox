//! commands 薄层：全部 #[tauri::command]（CONTRACT §3 逐字对齐）。
//!
//! 模块职责：
//! - dto.rs     前端 DTO（ItemSummaryDto / ItemDetailDto / SyncResultDto / …）
//! - local.rs   init_local / unlock_local / lock
//! - items.rs   item_create / item_update / item_delete / item_get / item_list
//! - save.rs    flush_now / change_password（含 flush_session 供关闭窗口时落盘）
//! - recover.rs recover_reset（忘记密码，答案档重包）
//! - remote.rs  remote_test / remote_register / remote_login / remote_logout + HTTP 客户端
//! - sync.rs    sync_now / sync_conflict_resolve
//!
//! 本文件另含跨模块共享小工具：会话守卫、后台阻塞任务（Argon2id 重计算）、
//! ping / app_info 两个无状态命令。

pub mod dto;
pub mod items;
pub mod local;
pub mod recover;
#[cfg(feature = "remote")]
pub mod remote;
pub mod save;
#[cfg(feature = "remote")]
pub mod sync;

use crate::error::VaultError;
use crate::state::{AppState, Session};
use crate::util::now_ms;

/// 连通自检（CONTRACT §3：返回 "pong"）。
#[tauri::command]
pub fn ping() -> Result<String, VaultError> {
    Ok("pong".to_string())
}

/// 关于信息（CONTRACT §3：{version, edition}）。
#[tauri::command]
pub fn app_info() -> Result<dto::AppInfoDto, VaultError> {
    Ok(dto::AppInfoDto {
        version: crate::APP_VERSION.to_string(),
        edition: if cfg!(feature = "remote") {
            "full".to_string()
        } else {
            "store".to_string()
        },
    })
}

/// 取会话守卫：未解锁（None）返回 not_unlocked。
/// 注意：guard 不得跨 await 持有；调用方在持有期间只做同步操作。
pub(crate) fn locked<'a>(
    state: &'a AppState,
) -> Result<std::sync::MutexGuard<'a, Option<Session>>, VaultError> {
    let guard = state.lock();
    if guard.is_none() {
        return Err(VaultError::NotUnlocked);
    }
    Ok(guard)
}

/// 变更即置脏 + 刷新活动时间（本地/远程统一入口）。
pub(crate) fn mark_dirty(sess: &mut Session) {
    sess.dirty = true;
    sess.last_activity_ms = now_ms();
}

/// 在 tauri 异步运行时的阻塞线程池上执行 CPU 重任务（Argon2id 64/128MiB、
/// 容器整体重写等），避免卡住 UI 线程。closure 返回 Result<T, VaultError>。
pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, VaultError> + Send + 'static,
) -> Result<T, VaultError> {
    match tauri::async_runtime::spawn_blocking(f).await {
        Ok(inner) => inner,
        Err(e) => Err(VaultError::Internal(format!("后台任务执行失败: {e}"))),
    }
}
