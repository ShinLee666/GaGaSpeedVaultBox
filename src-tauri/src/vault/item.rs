//! 条目级加密（CONTRACT §5 vault/item.rs；设计 §4.6）。
//!
//! 每条 item：ITEM_KEY = HKDF(DK, salt=item_salt 16B 随机, info="vaultbox.item.v1")；
//! cipher_blob = seal(ITEM_KEY, JSON 载荷, AAD="item:"+uuid)。
//! 载荷 JSON：`{"v":1,"kind":0|1|2,"title":"..","content":"..","note":".."}`
//! （kind: 0=账号 1=备注 2=密钥；note 可空）。
//! item_salt 每条独立随机（即使同 DK，不同条目密钥亦不同，爆破面切割到单条）。
//! 表内明文只落：uuid / cipher_blob / item_salt / kind / 时间戳（设计 §4.6）。

use serde::{Deserialize, Serialize};

use super::super::crypto::aead;
use super::super::crypto::derive::item_key;
use super::super::crypto::error::CryptoError;
use super::super::crypto::secret::{fill_random, Key32};

/// 条目类型枚举（明文，用于 UI 分组 / 排序）。
pub const KIND_ACCOUNT: u8 = 0; // 账号类
pub const KIND_NOTE: u8 = 1; // 备注类
pub const KIND_SECRET: u8 = 2; // 密钥类

/// 条目类型中文名（CLI 展示用）。
pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_ACCOUNT => "账号",
        KIND_NOTE => "备注",
        KIND_SECRET => "密钥",
        _ => "未知",
    }
}

/// 解密后的条目载荷（内存明文，用后即弃）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemPlain {
    pub kind: u8,
    pub title: String,
    pub content: String,
    pub note: Option<String>,
}

/// 落盘 JSON 载荷结构（v 为载荷版本，恒 1）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemPayloadJson {
    #[serde(default = "default_v")]
    pub v: u32,
    pub kind: u8,
    pub title: String,
    pub content: String,
    pub note: Option<String>,
}

fn default_v() -> u32 {
    1
}

/// 加密条目。返回 (item_salt 16B, cipher_blob)。
/// cipher_blob = nonce(12)||ct||tag(16)，可直接入库 items.cipher_blob。
pub fn encrypt_item(
    dk: &Key32,
    id: &str,
    kind: u8,
    title: &str,
    content: &str,
    note: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut salt = [0u8; 16];
    fill_random(&mut salt);
    let key = item_key(dk, &salt);
    let payload = ItemPayloadJson {
        v: 1,
        kind,
        title: title.to_string(),
        content: content.to_string(),
        note: note.map(|s| s.to_string()),
    };
    let json = serde_json::to_vec(&payload).map_err(|_| CryptoError::EncryptFailed)?;
    let mut aad = Vec::with_capacity(5 + id.len());
    aad.extend_from_slice(b"item:");
    aad.extend_from_slice(id.as_bytes());
    let blob = aead::seal(&key, &json, &aad)?;
    Ok((salt.to_vec(), blob))
}

/// 解密条目。
pub fn decrypt_item(
    dk: &Key32,
    id: &str,
    salt: &[u8],
    blob: &[u8],
) -> Result<ItemPlain, CryptoError> {
    let key = item_key(dk, salt);
    let mut aad = Vec::with_capacity(5 + id.len());
    aad.extend_from_slice(b"item:");
    aad.extend_from_slice(id.as_bytes());
    let pt = aead::open(&key, blob, &aad)?;
    let payload: ItemPayloadJson =
        serde_json::from_slice(&pt).map_err(|_| CryptoError::DecryptFailed)?;
    Ok(ItemPlain {
        kind: payload.kind,
        title: payload.title,
        content: payload.content,
        note: payload.note,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::random_key32;

    fn dk() -> Key32 {
        random_key32()
    }

    #[test]
    fn roundtrip_full_fields() {
        let k = dk();
        let (salt, blob) =
            encrypt_item(&k, "uuid-1", KIND_ACCOUNT, "银行", "账号: a / 密码: b", Some("备注1")).unwrap();
        assert_eq!(salt.len(), 16);
        assert!(blob.len() >= 28);
        let p = decrypt_item(&k, "uuid-1", &salt, &blob).unwrap();
        assert_eq!(
            p,
            ItemPlain {
                kind: KIND_ACCOUNT,
                title: "银行".to_string(),
                content: "账号: a / 密码: b".to_string(),
                note: Some("备注1".to_string()),
            }
        );
    }

    #[test]
    fn roundtrip_no_note_unicode() {
        let k = dk();
        let (salt, blob) = encrypt_item(&k, "id-中", KIND_NOTE, "标题 世界", "", None).unwrap();
        let p = decrypt_item(&k, "id-中", &salt, &blob).unwrap();
        assert_eq!(p.title, "标题 世界");
        assert_eq!(p.content, "");
        assert_eq!(p.note, None);
        assert_eq!(p.kind, KIND_NOTE);
    }

    #[test]
    fn wrong_id_fails_auth() {
        let k = dk();
        let (salt, blob) = encrypt_item(&k, "uuid-a", KIND_SECRET, "t", "c", None).unwrap();
        // AAD 绑定 id：换 id 解密必失败
        assert!(decrypt_item(&k, "uuid-b", &salt, &blob).is_err());
    }

    #[test]
    fn wrong_salt_fails() {
        let k = dk();
        let (_salt, blob) = encrypt_item(&k, "uuid-a", KIND_NOTE, "t", "c", None).unwrap();
        let other = [9u8; 16];
        assert!(decrypt_item(&k, "uuid-a", &other, &blob).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let k = dk();
        let (salt, mut blob) =
            encrypt_item(&k, "uuid-a", KIND_ACCOUNT, "t", "secret-content", Some("n")).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(decrypt_item(&k, "uuid-a", &salt, &blob).is_err());
        // 翻转 nonce 区
        let (salt2, mut blob2) =
            encrypt_item(&k, "uuid-a", KIND_ACCOUNT, "t", "secret-content", Some("n")).unwrap();
        blob2[0] ^= 0x80;
        assert!(decrypt_item(&k, "uuid-a", &salt2, &blob2).is_err());
    }

    #[test]
    fn same_plaintext_different_salt_blob() {
        let k = dk();
        let (s1, b1) = encrypt_item(&k, "id", KIND_NOTE, "same", "same", None).unwrap();
        let (s2, b2) = encrypt_item(&k, "id", KIND_NOTE, "same", "same", None).unwrap();
        // 每条 salt 独立随机 -> blob 全不同
        assert_ne!(s1, s2);
        assert_ne!(b1, b2);
        // 各自可解
        assert_eq!(decrypt_item(&k, "id", &s1, &b1).unwrap().title, "same");
        assert_eq!(decrypt_item(&k, "id", &s2, &b2).unwrap().title, "same");
    }

    #[test]
    fn kind_names() {
        assert_eq!(kind_name(0), "账号");
        assert_eq!(kind_name(1), "备注");
        assert_eq!(kind_name(2), "密钥");
        assert_eq!(kind_name(99), "未知");
    }
}
