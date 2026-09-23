//! 条目 CRUD 命令（CONTRACT §3：item_create / item_update / item_delete /
//! item_get / item_list）。本地与远程会话共用同一套逻辑：条目永远是
//! ITEM_KEY=HKDF(DK, item_salt) 的密文行，表结构相同，命令不区分模式；
//! 远程模式的“待推送”标记以 meta `dirty:<id>` / `pending_del:<id>` 记录，
//! 由 sync.rs 消费。

use tauri::State;

use crate::commands::dto::{self, ItemDetailDto, ItemSummaryDto};
use crate::commands::{locked, mark_dirty};
use crate::db::{memory, rows};
use crate::error::VaultError;
use crate::state::{AppState, SessionMode};
use crate::util::now_ms;
use crate::vault::item;

/// kind 取值合法性（0账号/1备注/2密钥）。
fn check_kind(kind: u8) -> Result<(), VaultError> {
    if kind > item::KIND_SECRET {
        return Err(VaultError::BadRequest(
            "kind 必须为 0(账号)/1(备注)/2(密钥)".to_string(),
        ));
    }
    Ok(())
}

/// 新建条目（CONTRACT §3：{kind,title,content,note?} -> ItemSummaryDto）。
#[tauri::command(rename_all = "snake_case")]
pub fn item_create(
    kind: u8,
    title: String,
    content: String,
    note: Option<String>,
    state: State<'_, AppState>,
) -> Result<ItemSummaryDto, VaultError> {
    check_kind(kind)?;
    if title.trim().is_empty() {
        return Err(VaultError::BadRequest("标题不能为空".to_string()));
    }
    let mut guard = locked(&state)?;
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    let id = uuid::Uuid::new_v4().to_string();
    let ts = now_ms();
    let (salt, blob) = item::encrypt_item(
        &sess.dk,
        &id,
        kind,
        &title,
        &content,
        note.as_deref(),
    )
    .map_err(VaultError::Crypto)?;
    rows::insert(&sess.db, &id, kind, &salt, &blob, ts, ts)?;
    if sess.mode == SessionMode::Remote {
        memory::meta_set(&sess.db, &format!("dirty:{id}"), "1")?;
    }
    mark_dirty(sess);
    Ok(ItemSummaryDto {
        id,
        kind,
        title,
        updated_at: ts,
    })
}

/// 更新条目（CONTRACT §3：{id,title,content,note?} -> null；kind 不可变）。
#[tauri::command(rename_all = "snake_case")]
pub fn item_update(
    id: String,
    title: String,
    content: String,
    note: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), VaultError> {
    if title.trim().is_empty() {
        return Err(VaultError::BadRequest("标题不能为空".to_string()));
    }
    let mut guard = locked(&state)?;
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    let row = rows::load_one(&sess.db, &id)?.ok_or(VaultError::NotFound)?;
    let kind = row.kind; // kind 不可变（与 CONTRACT 参数一致）
    let ts = now_ms();
    let (salt, blob) = item::encrypt_item(
        &sess.dk,
        &id,
        kind,
        &title,
        &content,
        note.as_deref(),
    )
    .map_err(VaultError::Crypto)?;
    rows::update_cipher(&sess.db, &id, kind, &salt, &blob, ts)?;
    if sess.mode == SessionMode::Remote {
        memory::meta_set(&sess.db, &format!("dirty:{id}"), "1")?;
    }
    mark_dirty(sess);
    Ok(())
}

/// 删除条目（CONTRACT §3：{id} -> null）。
#[tauri::command(rename_all = "snake_case")]
pub fn item_delete(id: String, state: State<'_, AppState>) -> Result<(), VaultError> {
    let mut guard = locked(&state)?;
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    let n = rows::delete(&sess.db, &id)?;
    if n == 0 {
        return Err(VaultError::NotFound);
    }
    if sess.mode == SessionMode::Remote {
        // 服务器上曾同步过该条目 -> 登记待删（sync_now 时 DELETE /items/:id）
        let rev = memory::meta_get(&sess.db, &format!("sync_rev:{id}"))?;
        if rev.is_some() {
            memory::meta_set(&sess.db, &format!("pending_del:{id}"), "1")?;
        }
        let _ = memory::meta_del(&sess.db, &format!("dirty:{id}"));
    }
    mark_dirty(sess);
    Ok(())
}

/// 取条目解密详情（CONTRACT §3：{id} -> ItemDetailDto）。
#[tauri::command(rename_all = "snake_case")]
pub fn item_get(id: String, state: State<'_, AppState>) -> Result<ItemDetailDto, VaultError> {
    let mut guard = locked(&state)?;
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    let row = rows::load_one(&sess.db, &id)?.ok_or(VaultError::NotFound)?;
    sess.last_activity_ms = now_ms();
    dto::row_to_detail(&sess.dk, &row)
}

/// 全量摘要列表（CONTRACT §3：item_list -> ItemSummaryDto[]）。
#[tauri::command]
pub fn item_list(state: State<'_, AppState>) -> Result<Vec<ItemSummaryDto>, VaultError> {
    let mut guard = locked(&state)?;
    let sess = guard.as_mut().ok_or(VaultError::NotUnlocked)?;
    sess.last_activity_ms = now_ms();
    dto::all_summaries(&sess.dk, &sess.db)
}
