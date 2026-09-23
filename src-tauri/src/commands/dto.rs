//! 前端 DTO（CONTRACT §3：字段 snake_case，与 TS interface 同名）。
//!
//! - ItemSummaryDto: {id, kind, title, updated_at}
//! - ItemDetailDto:  {id, kind, title, content, note?, created_at, updated_at}
//! - SyncResultDto:  {pulled, pushed, conflicts}
//! - RemoteTestResult: {ok, version?, error?}
//! 均为 serde 直出（字段名已是 snake_case，无需 rename）。

use serde::Serialize;

use crate::crypto::secret::Key32;
use crate::db::rows::{self, ItemRow};
use crate::error::VaultError;
use crate::vault::item::{self, ItemPlain};

/// 条目摘要（列表：title 为解密明文）。
#[derive(Debug, Clone, Serialize)]
pub struct ItemSummaryDto {
    pub id: String,
    pub kind: u8,
    pub title: String,
    pub updated_at: u64,
}

/// 条目详情（解密后）。
#[derive(Debug, Clone, Serialize)]
pub struct ItemDetailDto {
    pub id: String,
    pub kind: u8,
    pub title: String,
    pub content: String,
    pub note: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// 应用信息。
#[derive(Debug, Clone, Serialize)]
pub struct AppInfoDto {
    pub version: String,
    /// 发行版形态：full = 完整版（本地+联网）；store = 微软商店版（纯本地存储）。
    pub edition: String,
}

/// 远程连接测试结果（测试失败也走 Ok，由前端按字段展示）。
#[derive(Debug, Clone, Serialize)]
pub struct RemoteTestResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 同步结果计数。
#[derive(Debug, Clone, Default, Serialize)]
pub struct SyncResultDto {
    pub pulled: u64,
    pub pushed: u64,
    pub conflicts: u64,
}

/// 解密单条载荷；认证失败归类 Corrupt（密文被改/库损坏），其余底层错误包 Internal。
pub(crate) fn decrypt_plain(
    dk: &Key32,
    id: &str,
    salt: &[u8],
    blob: &[u8],
) -> Result<ItemPlain, VaultError> {
    item::decrypt_item(dk, id, salt, blob).map_err(|e| match e {
        crate::crypto::CryptoError::DecryptFailed => VaultError::Corrupt,
        other => VaultError::Crypto(other),
    })
}

/// 行 -> 摘要（解密 title）。
pub(crate) fn row_to_summary(dk: &Key32, row: &ItemRow) -> Result<ItemSummaryDto, VaultError> {
    let plain = decrypt_plain(dk, &row.id, &row.salt, &row.blob)?;
    Ok(ItemSummaryDto {
        id: row.id.clone(),
        kind: row.kind,
        title: plain.title,
        updated_at: row.updated_at,
    })
}

/// 行 -> 详情（解密 title/content/note）。
pub(crate) fn row_to_detail(dk: &Key32, row: &ItemRow) -> Result<ItemDetailDto, VaultError> {
    let plain = decrypt_plain(dk, &row.id, &row.salt, &row.blob)?;
    Ok(ItemDetailDto {
        id: row.id.clone(),
        kind: row.kind,
        title: plain.title,
        content: plain.content,
        note: plain.note,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// 全量摘要（item_list / unlock_local 的返回体）。任一条解密失败即报 Corrupt。
pub(crate) fn all_summaries(dk: &Key32, conn: &rusqlite::Connection) -> Result<Vec<ItemSummaryDto>, VaultError> {
    let rows = rows::load_all(conn)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(row_to_summary(dk, r)?);
    }
    Ok(out)
}
