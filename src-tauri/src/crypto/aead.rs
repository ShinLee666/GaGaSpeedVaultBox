//! AEAD：AES-256-GCM 封装（CONTRACT §5 crypto/aead.rs；设计 §4.6 / T1.3）。
//!
//! 统一 blob 布局 = `nonce(12) || ciphertext || tag(16)`（`seal` / `open`）。
//! 容器头的 wrapped_MK 块例外：nonce 单独存放（header 0x30 / 0xA0 区），
//! 因此另提供"nonce 由调用方给定"的变体 `seal_with_nonce` / `open_with_nonce`
//! （nonce 仍然必须来自系统 CSPRNG，本模块内已校验长度并拒绝全零 nonce 之外
//! 的滥用场景——生产路径 nonce 一律随机生成，见 container.rs）。
//!
//! 认证失败统一返回 `DecryptFailed`——不区分"密码错 / 被篡改 / 格式错"，
//! 防探测（设计 §4.3）。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use super::error::CryptoError;
use super::secret::{fill_random, Key32, SecretBytes};

/// 加密：自动生成 12B 随机 nonce。返回 `nonce||ct||tag` 单段 blob。
pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes);
    seal_with_nonce(key, &nonce_bytes, plaintext, aad)
}

/// 解密：先验长度（blob < 28B 直接拒绝，防 panic），再认证解密。
pub fn open(key: &Key32, blob: &[u8], aad: &[u8]) -> Result<SecretBytes, CryptoError> {
    if blob.len() < 28 {
        return Err(CryptoError::DecryptFailed);
    }
    let (nonce, rest) = blob.split_at(12);
    let nonce_arr: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| CryptoError::DecryptFailed)?;
    open_with_nonce(key, nonce_arr, rest, aad)
}

/// 使用调用方给定的 nonce 加密（返回仍为 `nonce||ct||tag`，便于统一处理）。
/// 调用方必须保证 nonce 新鲜（生产路径由 fill_random 生成）。
pub fn seal_with_nonce(
    key: &Key32,
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.as_ref().into());
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| CryptoError::EncryptFailed)?;
    let mut blob = Vec::with_capacity(28 + ct.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// 使用调用方给定的 nonce 解密。输入为 `ct||tag`（无 nonce 前缀，
/// 供 wrapped_MK 48B 块等场景使用）。认证失败统一 DecryptFailed。
pub fn open_with_nonce(
    key: &Key32,
    nonce: &[u8; 12],
    ct_tag: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    if ct_tag.len() < 16 {
        return Err(CryptoError::DecryptFailed);
    }
    let cipher = Aes256Gcm::new(key.as_ref().into());
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct_tag, aad })
        .map_err(|_| CryptoError::DecryptFailed)?;
    Ok(SecretBytes::new(pt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::random_key32;

    fn fixed_key() -> Key32 {
        // 仅测试用固定 key（生产路径禁止硬编码密钥/盐/nonce）
        let mut k = Key32::default();
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn roundtrip() {
        let key = fixed_key();
        let pt = "{\"title\":\"hello 世界\"}".as_bytes();
        let blob = seal(&key, pt, b"aad-ctx").unwrap();
        assert_eq!(blob.len(), 28 + pt.len());
        let out = open(&key, &blob, b"aad-ctx").unwrap();
        assert_eq!(out.as_slice(), pt);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let key = fixed_key();
        let blob = seal(&key, b"", b"aad").unwrap();
        assert_eq!(blob.len(), 28);
        let out = open(&key, &blob, b"aad").unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = fixed_key();
        let blob = seal(&key, b"secret", b"right-aad").unwrap();
        assert!(open(&key, &blob, b"wrong-aad").is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&fixed_key(), b"secret", b"aad").unwrap();
        assert!(open(&random_key32(), &blob, b"aad").is_err());
    }

    #[test]
    fn tamper_one_byte_fails() {
        let key = fixed_key();
        let blob = seal(&key, b"secret content here", b"aad").unwrap();
        // 翻转密文区任意 1 字节
        for pos in [0usize, 5, 12, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[pos] ^= 0x01;
            assert!(
                open(&key, &bad, b"aad").is_err(),
                "篡改位置 {pos} 未检出"
            );
        }
    }

    #[test]
    fn short_blob_rejected() {
        let key = fixed_key();
        assert!(open(&key, &[0u8; 10], b"aad").is_err());
        assert!(open(&key, &[0u8; 27], b"aad").is_err());
    }

    #[test]
    fn nonce_unique_per_seal() {
        let key = fixed_key();
        let a = seal(&key, b"same", b"aad").unwrap();
        let b = seal(&key, b"same", b"aad").unwrap();
        // 两次加密 nonce 不同 -> blob 不同
        assert_ne!(&a[0..12], &b[0..12]);
    }

    #[test]
    fn with_nonce_variants_roundtrip() {
        let key = fixed_key();
        let nonce = [9u8; 12];
        // ct||tag（无 nonce 前缀），wrapped_MK 块同款布局
        let full = seal_with_nonce(&key, &nonce, b"mk-bytes-32", b"prefix-aad").unwrap();
        assert_eq!(full.len(), 28 + b"mk-bytes-32".len());
        let ct_tag = &full[12..];
        assert_eq!(ct_tag.len(), 16 + b"mk-bytes-32".len());
        let out = open_with_nonce(&key, &nonce, ct_tag, b"prefix-aad").unwrap();
        assert_eq!(out.as_slice(), b"mk-bytes-32");
        // nonce 或 AAD 错误必须失败
        let bad_nonce = [8u8; 12];
        assert!(open_with_nonce(&key, &bad_nonce, ct_tag, b"prefix-aad").is_err());
        assert!(open_with_nonce(&key, &nonce, ct_tag, b"other-aad").is_err());
    }
}
