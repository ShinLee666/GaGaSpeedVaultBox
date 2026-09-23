//! 敏感内存类型与唯一随机源（CONTRACT §5 crypto/secret.rs；设计 T1.1）。
//!
//! 规则：所有密钥 / 口令 / 明文载荷一律用 `Zeroizing` 包装，Drop 即清零；
//! 随机数只经系统 CSPRNG（`OsRng`，Windows 上走 BCryptGenRandom）。

use rand::RngCore;
use zeroize::Zeroizing;

/// 32 字节密钥的统一类型：KEK / MK / DK / ITEM_KEY / AK。
pub type Key32 = Zeroizing<[u8; 32]>;

/// 敏感字节序列（口令、明文载荷等）。
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// 唯一允许生成"密钥级"随机数的入口：32B 系统 CSPRNG。
pub fn random_key32() -> Key32 {
    let mut k = Key32::default();
    rand::rngs::OsRng.fill_bytes(k.as_mut());
    k
}

/// 盐 / nonce 等非密钥随机数也统一走系统 CSPRNG（防误用弱随机源）。
pub fn fill_random(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// 把任意长度字节（如解出的 32B MK 明文）安全地搬进 Key32。
pub fn key32_from_slice(bytes: &[u8]) -> Option<Key32> {
    if bytes.len() != 32 {
        return None;
    }
    let mut k = Key32::default();
    k.copy_from_slice(bytes);
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_key32_unique_and_len() {
        let a = random_key32();
        let b = random_key32();
        assert_eq!(a.len(), 32);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn fill_random_changes_buffer() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        fill_random(&mut a);
        fill_random(&mut b);
        assert_ne!(&a, &b);
        // 几乎不可能全零
        assert!(!a.iter().all(|x| *x == 0));
    }

    #[test]
    fn key32_from_slice_length_check() {
        assert!(key32_from_slice(&[0u8; 31]).is_none());
        assert!(key32_from_slice(&[0u8; 33]).is_none());
        let k = key32_from_slice(&[7u8; 32]).unwrap();
        assert!(k.iter().all(|x| *x == 7));
    }
}
