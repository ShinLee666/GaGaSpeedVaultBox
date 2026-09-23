//! 同步命令：sync_now / sync_conflict_resolve（CONTRACT §3）。
//!
//! 同步模型（单用户多设备 MVP，冲突判定基于 rev + 本地脏标记）：
//! - 本地 meta 记录（远程会话的内存库内）：
//!     dirty:<id>="1"      条目自上次同步后有本地改动（item_* 命令登记）
//!     pending_del:<id>="1" 条目本地已删、待删除服务器副本
//!     sync_rev:<id>=hex    上次同步时服务器端的 rev（内容寻址，改动即变）
//!     sync_last_pull=ms    GET /items 的 since 游标
//! - sync_now：拉（since 之后服务器变更）-> 对账 -> 推（本地脏且未冲突）-> 删。
//!   同 id 两侧都变（本地 dirty 且服务器 rev 与已知不同）-> 冲突（存服务器行
//!   快照到 Session.pending_conflicts，等待 sync_conflict_resolve 三选一）。
//! - rev = SHA-256(salt||cipher_blob) hex（客户端计算，内容寻址）。
//! 条目密文与本地同构（ITEM_KEY=HKDF(DK,item_salt)，AAD=item:<id>），
//! 服务器行可直接落内存库、也可直接上行，全程不解密明文。

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use tauri::State;

use crate::commands::dto::SyncResultDto;
use crate::commands::remote::{
    delete_item, fetch_items_since, put_item, Api, ServerItem,
};
use crate::commands::{locked, mark_dirty};
use crate::db::{memory, rows, rows::ItemRow};
use crate::error::VaultError;
use crate::state::{AppState, RemoteConflict, SessionMode};
use crate::util::now_ms;

/// 内容寻址 rev：SHA-256(salt||cipher_blob) 的 hex（32B=64 hex）。
fn item_rev(salt: &[u8], blob: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(blob);
    hex::encode(h.finalize())
}

/// meta 表快照（sync 对账输入）。
struct MetaState {
    last_pull: u64,
    rev: HashMap<String, String>,
    dirty: HashSet<String>,
    pending_del: HashSet<String>,
}

fn load_meta(conn: &rusqlite::Connection) -> Result<MetaState, VaultError> {
    let mut stmt = conn.prepare("SELECT key,value FROM meta")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = MetaState {
        last_pull: 0,
        rev: HashMap::new(),
        dirty: HashSet::new(),
        pending_del: HashSet::new(),
    };
    for r in rows {
        let (k, v) = r?;
        if k == "sync_last_pull" {
            out.last_pull = v.parse().unwrap_or(0);
        } else if let Some(id) = k.strip_prefix("sync_rev:") {
            out.rev.insert(id.to_string(), v);
        } else if let Some(id) = k.strip_prefix("dirty:") {
            out.dirty.insert(id.to_string());
        } else if let Some(id) = k.strip_prefix("pending_del:") {
            out.pending_del.insert(id.to_string());
        }
    }
    Ok(out)
}

/// 手动同步（CONTRACT §3：sync_now -> {pulled,pushed,conflicts}；仅远程模式）。
#[tauri::command(rename_all = "snake_case")]
pub async fn sync_now(state: State<'_, AppState>) -> Result<SyncResultDto, VaultError> {
    // ---- 1) 快照（guard 不跨 await）----
    let (cfg, token, local_rows, meta, prev_conflicts) = {
        let mut g = locked(&state)?;
        let sess = g.as_mut().ok_or(VaultError::NotUnlocked)?;
        if sess.mode != SessionMode::Remote {
            return Err(VaultError::BadRequest(
                "仅远程模式支持手动同步".to_string(),
            ));
        }
        let cfg = sess
            .server_cfg
            .clone()
            .ok_or_else(|| VaultError::Internal("远程会话缺少服务器配置".to_string()))?;
        let token = sess
            .token
            .clone()
            .ok_or(VaultError::Unauthorized)?;
        let local_rows = rows::load_all(&sess.db)?;
        let meta = load_meta(&sess.db)?;
        let prev = sess.pending_conflicts.clone();
        (cfg, token, local_rows, meta, prev)
    };
    let api = Api::new(&cfg)?;

    // ---- 2) 拉取 since 游标之后的服务器条目并逐条对账 ----
    let server_items = fetch_items_since(&api, &token, meta.last_pull).await?;
    let mut pulls: Vec<ServerItem> = Vec::new(); // 以服务器为准，稍后落库
    let mut conflicts: Vec<RemoteConflict> = prev_conflicts; // 保留未决 + 新增
    let mut conflict_ids: HashSet<String> = conflicts.iter().map(|c| c.id.clone()).collect();

    for s in &server_items {
        if meta.pending_del.contains(&s.id) {
            continue; // 本地已删，删除优先（稍后 DELETE 服务器）
        }
        match local_rows.iter().find(|r| r.id == s.id) {
            None => pulls.push(s.clone()),
            Some(l) => {
                let known = meta.rev.get(&s.id);
                let rev_changed = known.map_or(true, |k| k != &s.rev);
                if !meta.dirty.contains(&s.id) {
                    if rev_changed {
                        pulls.push(s.clone());
                    }
                    // rev 相同：两侧都无新内容，跳过
                } else if rev_changed {
                    // 本地有改动且服务器也被别人改过 -> 冲突
                    if !conflict_ids.contains(&s.id) {
                        conflicts.push(RemoteConflict {
                            id: s.id.clone(),
                            server_kind: s.kind,
                            server_salt: hex::decode(&s.salt).unwrap_or_default(),
                            server_blob: hex::decode(&s.cipher).unwrap_or_default(),
                            server_created_at: s.created_at,
                            server_updated_at: s.updated_at,
                            server_rev: s.rev.clone(),
                            local_updated_at: l.updated_at,
                        });
                        conflict_ids.insert(s.id.clone());
                    }
                }
                // dirty 且服务器未变：交给推送阶段
            }
        }
    }

    // ---- 3) 删除本地已删条目在服务器上的副本 ----
    let mut deletes_done: Vec<String> = Vec::new();
    for id in &meta.pending_del {
        if conflict_ids.contains(id) {
            continue;
        }
        delete_item(&api, &token, id).await?;
        deletes_done.push(id.clone());
    }

    // ---- 4) 推送本地脏条目（跳过已冲突项）----
    struct PushDone {
        id: String,
        rev: String,
    }
    let mut pushes_done: Vec<PushDone> = Vec::new();
    for l in &local_rows {
        if !meta.dirty.contains(&l.id) || meta.pending_del.contains(&l.id) {
            continue;
        }
        if conflict_ids.contains(&l.id) {
            continue; // 等用户裁决
        }
        let rev = item_rev(&l.salt, &l.blob);
        let base_rev = meta.rev.get(&l.id).map(|s| s.as_str());
        let salt_hex = hex::encode(&l.salt);
        let blob_hex = hex::encode(&l.blob);
        match put_item(
            &api,
            &token,
            &l.id,
            l.kind,
            &salt_hex,
            &blob_hex,
            &rev,
            base_rev,
            l.updated_at,
        )
        .await
        {
            Ok(()) => pushes_done.push(PushDone {
                id: l.id.clone(),
                rev,
            }),
            Err(VaultError::Conflict(_)) => {
                // 服务器 rev 与我们已知不同且在我们推送前被改 -> 冲突（尚无服务器快照）
                if !conflict_ids.contains(&l.id) {
                    conflicts.push(RemoteConflict {
                        id: l.id.clone(),
                        server_kind: 0,
                        server_salt: Vec::new(),
                        server_blob: Vec::new(),
                        server_created_at: 0,
                        server_updated_at: 0,
                        server_rev: String::new(),
                        local_updated_at: l.updated_at,
                    });
                    conflict_ids.insert(l.id.clone());
                }
            }
            Err(e) => return Err(e),
        }
    }

    // ---- 5) 补齐冲突的服务器快照（409 型冲突无快照：全量拉一次对号入座；
    //         仍无数据的 = 服务器端已删除该条目）----
    if conflicts.iter().any(|c| c.server_salt.is_empty()) {
        let all = fetch_items_since(&api, &token, 0).await?;
        let map: HashMap<&str, &ServerItem> = all.iter().map(|i| (i.id.as_str(), i)).collect();
        for c in conflicts.iter_mut() {
            if c.server_salt.is_empty() {
                if let Some(s) = map.get(c.id.as_str()) {
                    c.server_kind = s.kind;
                    c.server_salt = hex::decode(&s.salt).unwrap_or_default();
                    c.server_blob = hex::decode(&s.cipher).unwrap_or_default();
                    c.server_created_at = s.created_at;
                    c.server_updated_at = s.updated_at;
                    c.server_rev = s.rev.clone();
                }
                // else：服务器已无此行（远端删除），server_rev 保持空 = 删除标记
            }
        }
    }

    // ---- 6) 应用（短锁，无 await）----
    {
        let mut g = locked(&state)?;
        let sess = g.as_mut().ok_or(VaultError::NotUnlocked)?;
        for it in &pulls {
            apply_server_row(sess, it)?;
        }
        for id in &deletes_done {
            let _ = memory::meta_del(&sess.db, &format!("sync_rev:{id}"));
            let _ = memory::meta_del(&sess.db, &format!("pending_del:{id}"));
            let _ = memory::meta_del(&sess.db, &format!("dirty:{id}"));
        }
        for p in &pushes_done {
            memory::meta_set(&sess.db, &format!("sync_rev:{}", p.id), &p.rev)?;
            let _ = memory::meta_del(&sess.db, &format!("dirty:{}", p.id));
            let _ = memory::meta_del(&sess.db, &format!("pending_del:{}", p.id));
        }
        let now = now_ms();
        memory::meta_set(&sess.db, "sync_last_pull", &now.to_string())?;
        let conflict_count = conflicts.len() as u64;
        sess.pending_conflicts = conflicts;
        sess.dirty = conflict_count > 0;
        sess.last_activity_ms = now;
        return Ok(SyncResultDto {
            pulled: pulls.len() as u64,
            pushed: pushes_done.len() as u64,
            conflicts: conflict_count,
        });
    }
}

/// 以服务器行覆盖本地（含 meta 指纹更新）。
fn apply_server_row(sess: &mut crate::state::Session, s: &ServerItem) -> Result<(), VaultError> {
    let salt = hex::decode(&s.salt).map_err(|_| VaultError::Corrupt)?;
    let blob = hex::decode(&s.cipher).map_err(|_| VaultError::Corrupt)?;
    let row = ItemRow {
        id: s.id.clone(),
        kind: s.kind,
        salt,
        blob,
        created_at: s.created_at,
        updated_at: s.updated_at,
    };
    rows::replace_row(&sess.db, &row)?;
    memory::meta_set(&sess.db, &format!("sync_rev:{}", s.id), &s.rev)?;
    let _ = memory::meta_del(&sess.db, &format!("dirty:{}", s.id));
    let _ = memory::meta_del(&sess.db, &format!("pending_del:{}", s.id));
    Ok(())
}

/// 冲突三选一（CONTRACT §3：{id,choice:"local"|"server"|"copy"} -> null）。
/// 前端契约约定 id='*' 表示处理全部冲突。
#[tauri::command(rename_all = "snake_case")]
pub async fn sync_conflict_resolve(
    id: String,
    choice: String,
    state: State<'_, AppState>,
) -> Result<(), VaultError> {
    match choice.as_str() {
        "local" | "server" | "copy" => {}
        other => {
            return Err(VaultError::BadRequest(format!(
                "choice 必须是 local/server/copy，收到: {other}"
            )))
        }
    }

    // ---- 1) 快照（guard 不跨 await）----
    enum Plan {
        /// 以本地为准：PUT 上行（base_rev=服务器当前 rev；空表示服务器已删 -> 重建）
        Push {
            row: ItemRow,
            base_rev: Option<String>,
        },
        /// 以服务器为准：用冲突快照覆盖本地
        ApplyServer { row: ItemRow, rev: String },
        /// 复制为新条目：本地明文 -> 新 uuid/新盐加密入库，原行删除
        CopyAsNew {
            orig_id: String,
            plain: crate::vault::item::ItemPlain,
            kind: u8,
        },
        /// 服务器已删 + 选择以服务器为准：删除本地行
        DropLocal,
        /// 本地行已不存在（竞态）：仅清冲突
        Noop,
    }
    let (cfg, token, dk, plans, target_ids) = {
        let mut g = locked(&state)?;
        let sess = g.as_mut().ok_or(VaultError::NotUnlocked)?;
        if sess.mode != SessionMode::Remote {
            return Err(VaultError::BadRequest(
                "仅远程模式支持冲突处理".to_string(),
            ));
        }
        let targets: Vec<RemoteConflict> = if id == "*" {
            sess.pending_conflicts.clone()
        } else {
            match sess.pending_conflicts.iter().find(|c| c.id == id) {
                Some(c) => vec![c.clone()],
                None => return Err(VaultError::NotFound),
            }
        };
        let mut plans = Vec::with_capacity(targets.len());
        for c in &targets {
            let local_row = rows::load_one(&sess.db, &c.id)?;
            let plan = match choice.as_str() {
                "local" => match local_row {
                    Some(l) => Plan::Push {
                        row: l,
                        base_rev: if c.server_rev.is_empty() {
                            None
                        } else {
                            Some(c.server_rev.clone())
                        },
                    },
                    None => Plan::Noop,
                },
                "copy" => match local_row {
                    Some(l) => {
                        let plain = crate::commands::dto::decrypt_plain(
                            &sess.dk,
                            &l.id,
                            &l.salt,
                            &l.blob,
                        )?;
                        Plan::CopyAsNew {
                            orig_id: c.id.clone(),
                            plain,
                            kind: l.kind,
                        }
                    }
                    None => Plan::Noop,
                },
                "server" => {
                    if c.server_salt.is_empty() {
                        Plan::DropLocal
                    } else {
                        Plan::ApplyServer {
                            row: ItemRow {
                                id: c.id.clone(),
                                kind: c.server_kind,
                                salt: c.server_salt.clone(),
                                blob: c.server_blob.clone(),
                                created_at: c.server_created_at,
                                updated_at: c.server_updated_at,
                            },
                            rev: c.server_rev.clone(),
                        }
                    }
                }
                _ => unreachable!("choice 已在上方校验"),
            };
            plans.push(plan);
        }
        let cfg = sess.server_cfg.clone().unwrap();
        let token = sess.token.clone().unwrap();
        let dk = sess.dk.clone();
        (cfg, token, dk, plans, targets.into_iter().map(|c| c.id).collect::<Vec<_>>())
    };

    // ---- 2) Push 计划走网络（无锁）----
    let mut push_results: HashMap<String, Result<String, VaultError>> = HashMap::new(); // id -> Ok(rev)
    let api = Api::new(&cfg)?;
    for (i, plan) in plans.iter().enumerate() {
        if let Plan::Push { row, base_rev } = plan {
            let rev = item_rev(&row.salt, &row.blob);
            let salt_hex = hex::encode(&row.salt);
            let blob_hex = hex::encode(&row.blob);
            let res = put_item(
                &api,
                &token,
                &row.id,
                row.kind,
                &salt_hex,
                &blob_hex,
                &rev,
                base_rev.as_deref(),
                row.updated_at,
            )
            .await;
            push_results.insert(target_ids[i].clone(), res.map(|_| rev));
        }
    }

    // ---- 3) 应用（短锁，无 await）----
    let mut resolved: HashSet<String> = HashSet::new();
    {
        let mut g = locked(&state)?;
        let sess = g.as_mut().ok_or(VaultError::NotUnlocked)?;
        for (i, plan) in plans.iter().enumerate() {
            let tid = &target_ids[i];
            match plan {
                Plan::Push { .. } => match push_results.get(tid) {
                    Some(Ok(rev)) => {
                        memory::meta_set(&sess.db, &format!("sync_rev:{tid}"), rev)?;
                        let _ = memory::meta_del(&sess.db, &format!("dirty:{tid}"));
                        let _ = memory::meta_del(&sess.db, &format!("pending_del:{tid}"));
                        resolved.insert(tid.clone());
                    }
                    Some(Err(e)) => return Err(clone_err(e)),
                    None => {}
                },
                Plan::ApplyServer { row, rev } => {
                    rows::replace_row(&sess.db, row)?;
                    memory::meta_set(&sess.db, &format!("sync_rev:{tid}"), rev)?;
                    let _ = memory::meta_del(&sess.db, &format!("dirty:{tid}"));
                    let _ = memory::meta_del(&sess.db, &format!("pending_del:{tid}"));
                    resolved.insert(tid.clone());
                }
                Plan::CopyAsNew {
                    orig_id,
                    plain,
                    kind,
                } => {
                    // 新条目
                    let new_id = uuid::Uuid::new_v4().to_string();
                    let ts = now_ms();
                    let (salt, blob) = crate::vault::item::encrypt_item(
                        &dk,
                        &new_id,
                        *kind,
                        &plain.title,
                        &plain.content,
                        plain.note.as_deref(),
                    )
                    .map_err(VaultError::Crypto)?;
                    rows::insert(&sess.db, &new_id, *kind, &salt, &blob, ts, ts)?;
                    // 原行删除；若服务器仍存在原行则留下其 rev 指纹防止被重新拉回
                    let _ = rows::delete(&sess.db, orig_id);
                    let _ = memory::meta_del(&sess.db, &format!("dirty:{orig_id}"));
                    let _ = memory::meta_del(&sess.db, &format!("pending_del:{orig_id}"));
                    if let Some(c) = sess
                        .pending_conflicts
                        .iter()
                        .find(|c| &c.id == orig_id)
                    {
                        if !c.server_rev.is_empty() {
                            memory::meta_set(
                                &sess.db,
                                &format!("sync_rev:{orig_id}"),
                                &c.server_rev,
                            )?;
                        }
                    }
                    memory::meta_set(&sess.db, &format!("dirty:{new_id}"), "1")?;
                    mark_dirty(sess);
                    resolved.insert(orig_id.clone());
                }
                Plan::DropLocal => {
                    let _ = rows::delete(&sess.db, tid);
                    let _ = memory::meta_del(&sess.db, &format!("sync_rev:{tid}"));
                    let _ = memory::meta_del(&sess.db, &format!("dirty:{tid}"));
                    let _ = memory::meta_del(&sess.db, &format!("pending_del:{tid}"));
                    resolved.insert(tid.clone());
                }
                Plan::Noop => {
                    let _ = memory::meta_del(&sess.db, &format!("dirty:{tid}"));
                    resolved.insert(tid.clone());
                }
            }
        }
        sess.pending_conflicts
            .retain(|c| !resolved.contains(&c.id));
        sess.dirty = !sess.pending_conflicts.is_empty() || sess.dirty;
        sess.last_activity_ms = now_ms();
    }
    Ok(())
}

/// 复制一份错误（VaultError 不可 Clone，按 code 重建给上层展示）。
fn clone_err(e: &VaultError) -> VaultError {
    use crate::error::VaultError as VE;
    match e {
        VE::Conflict(m) => VE::Conflict(m.clone()),
        VE::Unauthorized => VE::Unauthorized,
        VE::NotFound => VE::NotFound,
        VE::Unreachable => VE::Unreachable,
        VE::TlsError => VE::TlsError,
        VE::BadRequest(m) => VE::BadRequest(m.clone()),
        VE::WrongPassword => VE::WrongPassword,
        VE::AnswerWrong => VE::AnswerWrong,
        VE::Corrupt => VE::Corrupt,
        VE::AlreadyExists => VE::AlreadyExists,
        VE::NotUnlocked => VE::NotUnlocked,
        VE::WeakPassword(m) => VE::WeakPassword(m.clone()),
        VE::Internal(m) => VE::Internal(m.clone()),
        VE::Io(_) | VE::Sqlite(_) | VE::Json(_) | VE::Crypto(_) => {
            VE::Internal(e.to_string())
        }
    }
}
