//! KDF：Argon2id（CONTRACT §5 crypto/kdf.rs；设计 §4.2 / T1.2）。
//!
//! 参数档位（m 单位 MiB）：
//! - 密码档 `password_default()`：m=64MiB t=3 p=1（解锁体验与强度折中）；
//! - 答案档 `answer_default()`：m=128MiB t=4 p=1（答案熵低，成本加档）。
//! 派生输出统一 32B。盐长约定 16B（本模块校验 >= 8B 的 Argon2 下限）。

use argon2::{Algorithm, Argon2, Params, Version};

use super::error::CryptoError;
use super::secret::Key32;

/// Argon2id 参数。m_cost 单位 MiB（落容器头时为 1B 字段，<= 255）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// 密码档：64 MiB / 3 / 1。
    pub fn password_default() -> Self {
        Self {
            m_cost: 64,
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// 答案档：128 MiB / 4 / 1。
    pub fn answer_default() -> Self {
        Self {
            m_cost: 128,
            t_cost: 4,
            p_cost: 1,
        }
    }

    /// 编码为容器头里的 3 字节（m/t/p 各一字节）。
    pub fn to_bytes(&self) -> [u8; 3] {
        [self.m_cost as u8, self.t_cost as u8, self.p_cost as u8]
    }

    /// 从 3 字节解码并校验取值合法性（m 8..=255 MiB、t 1..=10、p 1..=4，
    /// 与服务器契约 §7 的校验区间一致）。
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != 3 {
            return Err(CryptoError::CorruptHeader);
        }
        let m = b[0] as u32;
        let t = b[1] as u32;
        let p = b[2] as u32;
        if !(8..=255).contains(&m) || !(1..=10).contains(&t) || !(1..=4).contains(&p) {
            return Err(CryptoError::CorruptHeader);
        }
        Ok(KdfParams {
            m_cost: m,
            t_cost: t,
            p_cost: p,
        })
    }
}

/// 唯一的口令派生入口。password/salt 使用方负责用完零化。
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    p: &KdfParams,
) -> Result<Key32, CryptoError> {
    // Argon2 盐下限 8 字节
    if salt.len() < 8 {
        return Err(CryptoError::KdfParam);
    }
    // Params 的内存单位是 KiB：MiB -> KiB 需乘 1024（高频坑位 #1）
    let params = Params::new(
        p.m_cost
            .checked_mul(1024)
            .ok_or(CryptoError::KdfParam)?,
        p.t_cost,
        p.p_cost,
        Some(32),
    )
    .map_err(|_| CryptoError::KdfParam)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Key32::default();
    argon
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secret::fill_random;
    use hex::encode;

    /// 黄金向量：Argon2id 官方交叉验证（m=32 MiB、t=3、p=4、输出 32B）：
    /// 密码 = 0x01..0x20（32B 递增），盐 = 0x01..0x10（16B 递增）。
    /// 期望输出 `4fa3bfb5...` 已用独立参考实现 argon2-cffi（libargon2 C 参考库，
    /// memory_cost=32768 KiB）交叉验证一致（见 docs-part3/31-rust.md 验证记录）。
    #[test]
    fn argon2id_golden_vector_cross_checked() {
        let password: Vec<u8> = (1u8..=32).collect();
        let salt: Vec<u8> = (1u8..=16).collect();
        let p = KdfParams {
            m_cost: 32, // 单位 MiB（即 32768 KiB，与交叉验证一致）
            t_cost: 3,
            p_cost: 4,
        };
        let out = derive_key(&password, &salt, &p).unwrap();
        assert_eq!(
            encode(out.as_ref()),
            "4fa3bfb55e773b08dd080d6791d8999becbedae42633a1faab98ba6f7bd86b56"
        );
    }

    #[test]
    fn same_password_salt_deterministic() {
        let p = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let salt = [3u8; 16];
        let a = derive_key(b"test-pass-1234", &salt, &p).unwrap();
        let b = derive_key(b"test-pass-1234", &salt, &p).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_salt_changes_output() {
        let p = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let a = derive_key(b"test-pass-1234", &s1, &p).unwrap();
        let b = derive_key(b"test-pass-1234", &s2, &p).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn params_roundtrip_and_bounds() {
        let p = KdfParams::password_default();
        assert_eq!(KdfParams::from_bytes(&p.to_bytes()).unwrap(), p);
        let q = KdfParams::answer_default();
        assert_eq!(KdfParams::from_bytes(&q.to_bytes()).unwrap(), q);
        // 越界参数拒绝
        assert!(KdfParams::from_bytes(&[1, 3, 1]).is_err()); // m 太小
        assert!(KdfParams::from_bytes(&[64, 0, 1]).is_err()); // t = 0
        assert!(KdfParams::from_bytes(&[64, 3, 9]).is_err()); // p 超上限
        assert!(KdfParams::from_bytes(&[64, 3]).is_err()); // 长度不足
    }

    #[test]
    fn salt_too_short_rejected() {
        let p = KdfParams::password_default();
        assert!(derive_key(b"pw", &[0u8; 4], &p).is_err());
    }

    #[test]
    fn random_salts_give_different_outputs_full_params() {
        // 用默认档位（64MiB）验证真实生产路径（含黄金向量之外的"随机盐"路径）
        let p = KdfParams::password_default();
        let mut s1 = [0u8; 16];
        let mut s2 = [0u8; 16];
        fill_random(&mut s1);
        fill_random(&mut s2);
        let a = derive_key(b"Correct-Horse-9!", &s1, &p).unwrap();
        let b = derive_key(b"Correct-Horse-9!", &s2, &p).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
