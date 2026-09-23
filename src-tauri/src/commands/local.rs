//! 本地模式命令：init_local / unlock_local / lock（CONTRACT §3）。
//!
//! 初始化与解锁都涉及 Argon2id（64MiB 起），重计算一律走
//! crate::commands::blocking（tauri 阻塞线程池），避免卡 UI。

use std::path::PathBuf;

use tauri::State;

use crate::commands::dto::{all_summaries, ItemSummaryDto};
use crate::commands::blocking;
use crate::crypto::secret::Key32;
use crate::db::memory;
use crate::error::VaultError;
use crate::state::{AppState, Session, SessionMode};
use crate::util::{normalize_answer, now_ms, validate_answer, validate_password};
use crate::vault::{container, item};

/// 数据目录下约定文件名：data/vault.vault（前端 useVault 同约定）。
pub(crate) fn vault_path_of(dir: &str) -> PathBuf {
    PathBuf::from(dir).join("vault.vault")
}

/// 初始化本地保险箱（CONTRACT §3：{dir,password,question?,answer?} -> ItemSummaryDto[]）。
/// dir 为数据目录，文件 = dir/vault.vault；成功后即解锁：安装会话并返回全量摘要。
#[tauri::command(rename_all = "snake_case")]
pub async fn init_local(
    dir: String,
    password: String,
    question: Option<String>,
    answer: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<ItemSummaryDto>, VaultError> {
    init_local_inner(&dir, &password, question, answer, &state).await
}

/// init_local 的实现内核（不依赖 tauri::State，便于单元测试直接驱动）。
pub(crate) async fn init_local_inner(
    dir: &str,
    password: &str,
    question: Option<String>,
    answer: Option<String>,
    state: &AppState,
) -> Result<Vec<ItemSummaryDto>, VaultError> {
    // 1) 参数校验（密码强度 / 问题答案成对与规范化，与 CLI init 同口径）
    validate_password(password)?;
    if question.is_some() != answer.is_some() {
        return Err(VaultError::BadRequest(
            "保护问题与答案必须同有同无".to_string(),
        ));
    }
    let answer_norm = answer.as_deref().map(normalize_answer);
    if let Some(ans) = &answer_norm {
        validate_answer(ans, password)?;
    }
    let path = vault_path_of(dir);

    let q_text = question.clone();
    let q_pair: Option<(String, String)> = match (q_text, answer_norm) {
        (Some(q), Some(a)) => Some((q, a)),
        _ => None,
    };
    let path2 = path.clone();
    let pw2 = password.to_string();
    // 1.5) 新建前丢弃任何旧会话（与 unlock_local 同口径：重新进入已解锁态）
    {
        let mut guard = state.lock();
        *guard = None;
    }
    // 2) 建库（meta）-> 建容器 -> 解锁 -> 写欢迎条目 -> 落盘（全在阻塞线程）
    //    直接把 (mk, dk, conn) 带出，供安装会话使用
    let (mk, dk, conn) = blocking(move || -> Result<(Key32, Key32, rusqlite::Connection), VaultError> {
        if path2.exists() {
            return Err(VaultError::AlreadyExists);
        }
        if let Some(parent) = path2.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = memory::open_empty()?;
        let ts = now_ms();
        memory::meta_set(&conn, "schema_version", "1")?;
        memory::meta_set(&conn, "created_at", &ts.to_string())?;
        memory::meta_set(&conn, "last_saved_at", &ts.to_string())?;
        let db1 = memory::export_bytes(&conn)?;

        let q_pair_ref = q_pair
            .as_ref()
            .map(|(q, a)| (q.as_str(), a.as_bytes()));
        container::create_vault(&path2, pw2.as_bytes(), &db1, q_pair_ref)?;

        // 解锁后追加欢迎条目再整体保存（与 CLI init 行为一致）
        let (_hdr, mk, dk, db_bytes, _q) = container::unlock_vault(&path2, pw2.as_bytes())?;
        let conn2 = memory::import_bytes(&db_bytes)?;
        let welcome = format!(
            "欢迎使用 VaultBox！本保险箱创建于 {}。\n此条目为系统自动生成的欢迎信息，可以删除。",
            ts
        );
        let id = uuid::Uuid::new_v4().to_string();
        let (salt, blob) = item::encrypt_item(
            &dk,
            &id,
            item::KIND_NOTE,
            "欢迎使用 VaultBox",
            &welcome,
            None,
        )
        .map_err(VaultError::Crypto)?;
        crate::db::rows::insert(&conn2, &id, item::KIND_NOTE, &salt, &blob, ts, ts)?;
        memory::meta_set(&conn2, "last_saved_at", &now_ms().to_string())?;
        let db2 = memory::export_bytes(&conn2)?;
        container::rewrite_vault(&path2, &_hdr, &mk, &db2)?;
        // 内存库换用含欢迎条目的 conn2，与磁盘完全一致
        Ok((mk, dk, conn2))
    })
    .await?;

    // 3) 安装会话（创建即解锁）并返回全量摘要
    let summaries = all_summaries(&dk, &conn)?;
    {
        let mut guard = state.lock();
        *guard = Some(Session {
            mode: SessionMode::Local,
            vault_path: Some(path),
            server_cfg: None,
            token: None,
            mk,
            dk,
            db: conn,
            dirty: false,
            pending_conflicts: Vec::new(),
            last_activity_ms: now_ms(),
        });
    }
    Ok(summaries)
}

/// 解锁本地保险箱（CONTRACT §3：{path,password} -> ItemSummaryDto[]）。
/// 成功后安装会话（Session{Local, mk, dk, db, …}）并返回全量摘要。
#[tauri::command(rename_all = "snake_case")]
pub async fn unlock_local(
    path: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<Vec<ItemSummaryDto>, VaultError> {
    // 已有会话（未锁）时先丢弃，重新解锁
    {
        let mut guard = state.lock();
        *guard = None;
    }

    let path_pb = PathBuf::from(&path);
    let pw2 = password.clone();
    let path_for_closure = path_pb.clone();
    let (mk, dk, conn) = blocking(move || -> Result<(Key32, Key32, rusqlite::Connection), VaultError> {
        let (_hdr, mk, dk, db_bytes, _q) = container::unlock_vault(&path_for_closure, pw2.as_bytes())?;
        let conn = memory::import_bytes(&db_bytes)?;
        Ok((mk, dk, conn))
    })
    .await?;

    let summaries = all_summaries(&dk, &conn)?;
    {
        let mut guard = state.lock();
        *guard = Some(Session {
            mode: SessionMode::Local,
            vault_path: Some(path_pb),
            server_cfg: None,
            token: None,
            mk,
            dk,
            db: conn,
            dirty: false,
            pending_conflicts: Vec::new(),
            last_activity_ms: now_ms(),
        });
    }
    Ok(summaries)
}

/// 立即锁定：清空会话（Key32/内存库随 Drop 零化，CONTRACT §3 -> null）。
#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> Result<(), VaultError> {
    let mut guard = state.lock();
    *guard = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    //! 回归测试：init_local 成功后必须直接处于解锁态（安装会话）。
    //!
    //! 背景：0.1.0 初版 init_local 只写盘不装会话，前端已置 unlocked=true
    //! 并进入主页，但后端 AppState 仍为 None（锁定），任何命令报 not_unlocked，
    //! 用户只能"锁定→再解锁"才能正常使用。本测试锁死该行为：
    //! init_local_inner 返回后 ① 会话存在 ② 返回欢迎条目摘要 ③ 重复初始化报错。
    use super::*;

    fn temp_dir(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("vaultbox_ut_{}_{}", tag, uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string()
    }

    const PW: &str = "Test-Password-123";

    #[test]
    fn init_installs_session_and_returns_summaries() {
        let state = AppState::new();
        let dir = temp_dir("init");
        assert!(state.lock().is_none());

        let summaries = tauri::async_runtime::block_on(init_local_inner(
            &dir,
            PW,
            Some("我的真实姓名".to_string()),
            Some("答案短语一二三四".to_string()),
            &state,
        ))
        .expect("init_local_inner 应成功");

        // ① 返回全量摘要，含欢迎条目
        assert_eq!(summaries.len(), 1, "应返回 1 条欢迎条目摘要");
        assert!(summaries[0].title.contains("欢迎"));

        // ② 会话已安装 = 解锁态（item_list 等命令可直接用）
        {
            let guard = state.lock();
            let sess = guard.as_ref().expect("init 后必须存在会话");
            assert_eq!(sess.mode, SessionMode::Local);
            assert!(!sess.dirty, "新建保险箱不应有未保存标记");
            let again = all_summaries(&sess.dk, &sess.db).expect("会话内应可列条目");
            assert_eq!(again.len(), 1);
        }

        // 清理：锁 + 删临时目录
        *state.lock() = None;
        assert!(state.lock().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_rejects_existing_vault() {
        let state = AppState::new();
        let dir = temp_dir("dup");

        tauri::async_runtime::block_on(init_local_inner(&dir, PW, None, None, &state))
            .expect("首次初始化应成功");

        // 同路径重复初始化 -> AlreadyExists（前端据此引导去解锁页）
        let second = tauri::async_runtime::block_on(init_local_inner(&dir, PW, None, None, &state));
        assert!(matches!(second, Err(VaultError::AlreadyExists)));

        *state.lock() = None;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
