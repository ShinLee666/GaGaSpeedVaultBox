//! HKDF-SHA256 派生模块（CONTRACT §5 crypto/derive.rs；设计 §4.2 / T1.4）。
//!
//! 密钥体系（CONTRACT §1）：
//! - DK       = HKDF(MK,  salt=SALT2,           info="vaultbox.data.v1")
//! - ITEM_KEY = HKDF(DK,  salt=item_salt(16B随机), info="vaultbox.item.v1")
//! - AK       = HKDF(KEK, salt=空,               info="vaultbox.auth.v1")  // 联网认证
//! info 常量全仓唯一；HKDF 的 salt 仅做域分离，不保密（与 Argon2 盐是两回事）。

use hkdf::Hkdf;
use sha2::Sha256;

use super::secret::Key32;

/// MK -> DK 的派生上下文盐（固定、非秘密）。
pub const SALT2: &[u8; 16] = b"vaultbox-salt2!!";
/// MK -> DK 的 info。
pub const INFO_DATA: &[u8] = b"vaultbox.data.v1";
/// DK + item_salt -> ITEM_KEY 的 info。
pub const INFO_ITEM: &[u8] = b"vaultbox.item.v1";
/// KEK -> AK 的 info（联网认证用）。
pub const INFO_AUTH: &[u8] = b"vaultbox.auth.v1";

fn expand(ikm: &[u8], salt: &[u8], info: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Key32::default();
    // 32B <= 255*32B，必然成功
    hk.expand(info, okm.as_mut()).expect("32B always fits");
    okm
}

/// 数据密钥：MK -> DK。
pub fn data_key(mk: &Key32) -> Key32 {
    expand(mk.as_ref(), SALT2, INFO_DATA)
}

/// 条目密钥：DK + 随机 item_salt(16B) -> ITEM_KEY。
pub fn item_key(dk: &Key32, item_salt: &[u8]) -> Key32 {
    expand(dk.as_ref(), item_salt, INFO_ITEM)
}

/// 认证密钥：KEK -> AK（联网模式 verifier 的前身，见 commands/remote）。
pub fn auth_key(kek: &Key32) -> Key32 {
    expand(kek.as_ref(), &[], INFO_AUTH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::random_key32;

    #[test]
    fn data_key_deterministic() {
        let mk = random_key32();
        assert_eq!(data_key(&mk).as_ref(), data_key(&mk).as_ref());
    }

    #[test]
    fn data_key_differs_across_mk() {
        let a = data_key(&random_key32());
        let b = data_key(&random_key32());
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn item_key_varies_with_salt() {
        let dk = random_key32();
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let k1 = item_key(&dk, &s1);
        let k2 = item_key(&dk, &s2);
        assert_ne!(k1.as_ref(), k2.as_ref());
        // 同盐确定性
        assert_eq!(item_key(&dk, &s1).as_ref(), item_key(&dk, &s1).as_ref());
    }

    #[test]
    fn item_key_differs_from_data_key() {
        // 域分离：同一 mk 下 DK 与任何 ITEM_KEY 均不同
        let mk = random_key32();
        let dk = data_key(&mk);
        assert_ne!(dk.as_ref(), item_key(&dk, &[0u8; 16]).as_ref());
    }

    #[test]
    fn auth_key_deterministic_and_distinct() {
        let kek = random_key32();
        assert_eq!(auth_key(&kek).as_ref(), auth_key(&kek).as_ref());
        assert_ne!(auth_key(&kek).as_ref(), kek.as_ref());
    }

    #[test]
    fn data_key_salt2_constant_len16() {
        assert_eq!(SALT2.len(), 16);
    }
}
