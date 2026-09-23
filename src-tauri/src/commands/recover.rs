//! 忘记密码恢复：recover_reset（CONTRACT §3：{path,answer,new_password} -> null）。
//!
//! 与 CLI reset 同语义：读头部 -> 用保护问题答案（NFKC 规范化，答案档
//! Argon2id m=128MiB）解开 wrapped_MK_Q 取得 MK -> repack_mk 用新密码重包，
//! 保护问题一并清除（前端可再次走设置流程重建）。

use std::path::PathBuf;

use tauri::State;

use crate::commands::blocking;
use crate::crypto::aead;
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::secret::key32_from_slice;
use crate::error::VaultError;
use crate::state::AppState;
use crate::util::{normalize_answer, validate_password};
use crate::vault::container;

/// 忘记密码：答案验证通过后以新密码重包（CONTRACT §3）。
#[tauri::command(rename_all = "snake_case")]
pub async fn recover_reset(
    path: String,
    answer: String,
    new_password: String,
    _state: State<'_, AppState>,
) -> Result<(), VaultError> {
    validate_password(&new_password)?;
    let answer_norm = normalize_answer(&answer);
    if answer_norm.chars().count() < 8 {
        return Err(VaultError::BadRequest(
            "保护问题答案至少 8 个字符".to_string(),
        ));
    }

    // 快速预检：存在性问题文本/未设保护问题 -> 明确报错（不上 Argon）
    let pb = PathBuf::from(&path);
    let hdr = container::read_header(&pb)?;
    let salt_q = hdr
        .salt_q
        .ok_or_else(|| VaultError::BadRequest("该保险箱未设置保护问题，无法用答案重置".to_string()))?;
    let nonce_kek = hdr.nonce_kek;
    let wrapped_mk_q = hdr
        .wrapped_mk_q
        .ok_or(VaultError::Corrupt)?;
    let aad = hdr.aad_mk();

    let pb2 = pb.clone();
    let ans2 = answer_norm.clone();
    let new2 = new_password.clone();
    blocking(move || -> Result<(), VaultError> {
        // 1) 答案档派生 KEK_Q 并解开 wrapped_MK_Q（认证失败 = 答案错）
        let kek_q = kdf::derive_key(ans2.as_bytes(), &salt_q, &KdfParams::answer_default())?;
        let mk_bytes = aead::open_with_nonce(&kek_q, &nonce_kek, &wrapped_mk_q, &aad)
            .map_err(|_| VaultError::AnswerWrong)?;
        let mk = key32_from_slice(&mk_bytes).ok_or(VaultError::Corrupt)?;
        // 2) 以新密码重包（问题清除，与 CLI reset 语义一致）
        container::repack_mk(&pb2, &mk, new2.as_bytes(), None)
    })
    .await?;
    Ok(())
}
