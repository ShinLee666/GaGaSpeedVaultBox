//! 保存与改密命令：flush_now / change_password（CONTRACT §3）。
//!
//! flush 语义：内存库 export_bytes -> rewrite_vault（全量重建密文段，容器.rs
//! 内部已实现 tmp+fsync+滚动 .bak1/.bak2+原子 rename 的写安全），零散落在本层。
//! 远程模式没有本地容器，flush 视为无操作（同步由 sync_now 显式触发）。

use tauri::State;

use crate::commands::{blocking, locked};
use crate::crypto::aead;
use crate::crypto::kdf;
use crate::db::memory;
use crate::error::VaultError;
use crate::state::{AppState, Session, SessionMode};
use crate::util::{now_ms, validate_password};
use crate::vault::container;

/// 把会话落盘（本地模式）。远程模式无操作返回 Ok。
/// 供 flush_now 命令与 lib.rs 关闭窗口事件共用。
pub fn flush_session(sess: &mut Session) -> Result<(), VaultError> {
    match sess.mode {
        SessionMode::Local => {
            let path = sess
                .vault_path
                .clone()
                .ok_or_else(|| VaultError::Internal("本地会话缺少容器路径".to_string()))?;
            let mk = sess.mk.clone();
            let db_bytes = memory::export_bytes(&sess.db)?.to_vec();
            let hdr = container::read_header(&path)?;
            container::rewrite_vault(&path, &hdr, &mk, &db_bytes)?;
            memory::meta_set(&sess.db, "last_saved_at", &now_ms().to_string())?;
            sess.dirty = false;
            Ok(())
        }
        SessionMode::Remote => Ok(()),
    }
}

/// 立即保存（CONTRACT §3：flush_now -> null）。
#[tauri::command]
pub fn flush_now(state: State<'_, AppState>) -> Result<(), VaultError> {
    let mut guard = state.lock();
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    flush_session(sess)
}

/// 修改密码（CONTRACT §3：{current,new_password} -> null；仅本地模式）。
/// 验证 current 能解开 wrapped_MK 且与内存 MK 一致 -> 重包（salt1/nonce_kek
/// 刷新、wrapped_MK_Q 保留），MK/DK 不变，会话保持解锁。
#[tauri::command(rename_all = "snake_case")]
pub async fn change_password(
    current: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), VaultError> {
    validate_password(&new_password)?;

    // 快照：路径 + MK + 库字节（guard 不跨 await）
    let (path, mk, db_bytes) = {
        let mut guard = locked(&state)?;
        let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
        if sess.mode != SessionMode::Local {
            return Err(VaultError::BadRequest(
                "远程模式暂不支持本地改密（请用服务器端账户体系）".to_string(),
            ));
        }
        let path = sess
            .vault_path
            .clone()
            .ok_or_else(|| VaultError::Internal("本地会话缺少容器路径".to_string()))?;
        let db_bytes = memory::export_bytes(&sess.db)?.to_vec();
        (path, sess.mk.clone(), db_bytes)
    };

    let path2 = path.clone();
    let cur2 = current.clone();
    let new2 = new_password.clone();
    blocking(move || -> Result<(), VaultError> {
        // 1) 校验当前密码：解开 wrapped_MK 并与会话 MK 比对
        let hdr = container::read_header(&path2)?;
        let kek = kdf::derive_key(cur2.as_bytes(), &hdr.salt1, &hdr.kdf)?;
        let aad = hdr.aad_mk();
        let mk_bytes = aead::open_with_nonce(&kek, &hdr.nonce_kek, &hdr.wrapped_mk, &aad)
            .map_err(|_| VaultError::WrongPassword)?;
        if mk_bytes.as_slice() != mk.as_ref() {
            return Err(VaultError::WrongPassword);
        }
        // 2) 重包（保持既有保护问题与 wrapped_MK_Q）
        container::rewrap_password(&path2, &mk, &db_bytes, new2.as_bytes())
    })
    .await?;

    let mut guard = state.lock();
    if let Some(sess) = guard.as_mut() {
        if sess.mode == SessionMode::Local && sess.vault_path.as_deref() == Some(path.as_path()) {
            sess.dirty = false;
        }
    }
    Ok(())
}
