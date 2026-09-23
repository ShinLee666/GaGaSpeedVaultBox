//! 容器头部：定长 0x100=256 字节的精确编解码（CONTRACT §5 vault/header.rs；
//! 布局严格按主文档 §4.5 偏移表，不做 serde——字节格式必须手工精确控制）。
//!
//! 偏移表（小端，多字节字符串一律 UTF-8）：
//! ```text
//! 0x000  8   MAGIC "VLTB0X01"
//! 0x008  2   header_len（当前 0x0100 = 256）
//! 0x00A  1   kdf_alg（0x01 = Argon2id）
//! 0x00B  3   kdf_m / kdf_t / kdf_p（m 单位 MiB）
//! 0x00E  1   cipher_alg（0x01 = AES-256-GCM）
//! 0x00F  1   flags（bit0: 条目级加密启用）
//! 0x010  16  salt1（密码 KEK 派生盐）
//! 0x020  16  salt_Q（答案 KEK_Q 派生盐；无保护问题则全 0xFF）
//! 0x030  12  nonce_kek（包裹 MK 的 GCM nonce）
//! 0x03C  48  wrapped_MK（AES-256-GCM(KEK, MK) = ct||tag；AAD=头 0x000..0x03C）
//! 0x06C  48  wrapped_MK_Q（可选块；salt_Q 区为 0xFF 时无意义）
//! 0x09C  4   body_len（密文体总长，含 nonce 与 tag，见 container.rs 说明）
//! 0x0A0  12  nonce_body（密文体 GCM nonce，与密文体头部 12B 一致的双写）
//! 0x0AC  84  预留区（全随机填充；当 salt_Q 存在时，前 1B 记录问题文本
//!             长度 q_len(<=80)，随后 q_len 字节为问题文本 UTF-8——这是
//!             "忘记密码"流程在不解密 body 的情况下能显示问题文本的关键）
//! 0x100     密文体  AES-256-GCM(DK, 载荷)；AAD = 整个 256B 头部
//! ```
//!
//! 说明：CONTRACT 规定 blob 布局 = nonce(12)||ct||tag(16)，因此密文体区
//! 直接写整段 seal 输出（含 nonce），header.nonce_body 为其镜像双写，
//! body_len = 密文段总长；打开时校验两者一致，不一致判 Corrupt。

use crate::crypto::error::CryptoError;
use crate::crypto::kdf::KdfParams;
use crate::crypto::secret::fill_random;

/// 魔数（联网缓存同格式）。
pub const MAGIC: [u8; 8] = *b"VLTB0X01";
/// 头部总长（0x100 = 256 字节，含预留区）。
pub const HEADER_LEN: usize = 0x100;
/// 容器/头部版本（当前 0x0100）。
pub const VERSION: u16 = 0x0100;
/// KDF 算法标识：Argon2id。
pub const KDF_ALG_ARGON2ID: u8 = 0x01;
/// 加密算法标识：AES-256-GCM。
pub const CIPHER_AES256GCM: u8 = 0x01;
/// flags bit0：条目级加密启用（本项目恒置 1）。
pub const FLAG_ITEM_ENC: u8 = 0x01;
/// flags bit1：载荷已压缩（zstd，本项目未用）。
pub const FLAG_COMPRESSED: u8 = 0x02;
/// 预留区起始偏移（0xAC）。
pub const RESERVED_OFF: usize = 0x0AC;
/// 预留区内问题文本最大长度（0xAC 之后 1B 长度 + 文本，上限 80 字节）。
pub const QUESTION_MAX_LEN: usize = 80;

/// 容器头部结构。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHeader {
    /// Argon2id 参数（m 单位 MiB）。
    pub kdf: KdfParams,
    /// 密码 KEK 派生盐（16B）。
    pub salt1: [u8; 16],
    /// 答案 KEK_Q 派生盐；None = 未设保护问题（区 0xFF）。
    pub salt_q: Option<[u8; 16]>,
    /// 包裹 MK 的 GCM nonce（12B）。
    pub nonce_kek: [u8; 12],
    /// AES-256-GCM(KEK, MK) = ct(32)||tag(16)，共 48B。
    pub wrapped_mk: [u8; 48],
    /// AES-256-GCM(KEK_Q, MK)，可选块。
    pub wrapped_mk_q: Option<[u8; 48]>,
    /// 密文体总长（含 nonce+tag 的 seal 输出长度）。
    pub body_len: u32,
    /// 密文体 GCM nonce（与密文体头部 12B 双写一致）。
    pub nonce_body: [u8; 12],
    /// flags 字节。
    pub flags: u8,
    /// 保护问题文本（UTF-8，<=80B；存于预留区。None = 无问题）。
    pub question: Option<String>,
}

impl VaultHeader {
    /// 新头部：所有随机区由调用方填充；这里仅做默认初始化（全零），
    /// 生产路径请用 crate::vault::container 提供的创建函数。
    pub fn fresh() -> Self {
        VaultHeader {
            kdf: KdfParams::password_default(),
            salt1: [0u8; 16],
            salt_q: None,
            nonce_kek: [0u8; 12],
            wrapped_mk: [0u8; 48],
            wrapped_mk_q: None,
            body_len: 0,
            nonce_body: [0u8; 12],
            flags: FLAG_ITEM_ENC,
            question: None,
        }
    }

    /// wrapped_MK / wrapped_MK_Q 的加密 AAD = 头部 0x000..0x03C 字节
    /// （不含 wrapped_MK 本身，防自引用）。此 60 字节全部为确定性字段
    /// （不含随机预留区），可独立重算，因此支持"先算 AAD 再定 wrapped_MK"。
    pub fn aad_mk(&self) -> [u8; 0x3C] {
        let mut out = [0u8; 0x3C];
        out[0..8].copy_from_slice(&MAGIC);
        out[8..10].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[10] = KDF_ALG_ARGON2ID;
        out[11..14].copy_from_slice(&self.kdf.to_bytes());
        out[14] = CIPHER_AES256GCM;
        out[15] = self.flags;
        out[16..32].copy_from_slice(&self.salt1);
        match &self.salt_q {
            Some(sq) => out[32..48].copy_from_slice(sq),
            None => out[32..48].fill(0xFF),
        }
        out[48..60].copy_from_slice(&self.nonce_kek);
        out
    }

    /// 序列化为 256B 头部。注意：预留区每次调用重新随机填充，
    /// 因此同一结构两次 to_bytes 结果不同（每次保存密文全新，符合设计）。
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        b[10] = KDF_ALG_ARGON2ID;
        b[11..14].copy_from_slice(&self.kdf.to_bytes());
        b[14] = CIPHER_AES256GCM;
        b[15] = self.flags;
        b[16..32].copy_from_slice(&self.salt1);
        match &self.salt_q {
            Some(sq) => b[32..48].copy_from_slice(sq),
            None => b[32..48].fill(0xFF),
        }
        b[48..60].copy_from_slice(&self.nonce_kek);
        b[60..108].copy_from_slice(&self.wrapped_mk);
        match &self.wrapped_mk_q {
            Some(w) => b[108..156].copy_from_slice(w),
            None => b[108..156].fill(0x00),
        }
        b[156..160].copy_from_slice(&self.body_len.to_le_bytes());
        b[160..172].copy_from_slice(&self.nonce_body);
        // 预留区 0xAC..：有保护问题时写问题文本（1B 长度 + UTF-8）
        if let (Some(_sq), Some(q)) = (&self.salt_q, &self.question) {
            debug_assert!(q.len() <= QUESTION_MAX_LEN, "问题文本超过 80 字节");
            let n = q.len().min(QUESTION_MAX_LEN);
            b[RESERVED_OFF] = n as u8;
            b[RESERVED_OFF + 1..RESERVED_OFF + 1 + n].copy_from_slice(&q.as_bytes()[..n]);
            // 剩余预留区随机填充（伪装 + 版本演进空间）
            fill_random(&mut b[RESERVED_OFF + 1 + n..]);
        } else {
            fill_random(&mut b[RESERVED_OFF..]);
        }
        b
    }

    /// 解析 256B 头部。校验顺序：长度 -> MAGIC -> header_len -> kdf_alg ->
    /// cipher_alg -> flags -> kdf 参数合法 -> salt 区标记。
    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() < HEADER_LEN {
            return Err(CryptoError::BadLength);
        }
        if b[0..8] != MAGIC {
            return Err(CryptoError::CorruptHeader);
        }
        let hlen = u16::from_le_bytes([b[8], b[9]]);
        if hlen as usize != HEADER_LEN {
            return Err(CryptoError::UnsupportedVersion);
        }
        if b[10] != KDF_ALG_ARGON2ID {
            return Err(CryptoError::UnsupportedVersion);
        }
        if b[14] != CIPHER_AES256GCM {
            return Err(CryptoError::UnsupportedVersion);
        }
        let flags = b[15];
        if flags & FLAG_ITEM_ENC == 0 {
            // 本项目恒启用条目级加密；没有该位视为旧版/不支持的容器
            return Err(CryptoError::UnsupportedVersion);
        }
        let kdf = KdfParams::from_bytes(&b[11..14])?;

        let mut salt1 = [0u8; 16];
        salt1.copy_from_slice(&b[16..32]);
        let mut nonce_kek = [0u8; 12];
        nonce_kek.copy_from_slice(&b[48..60]);
        let mut wrapped_mk = [0u8; 48];
        wrapped_mk.copy_from_slice(&b[60..108]);
        let mut nonce_body = [0u8; 12];
        nonce_body.copy_from_slice(&b[160..172]);
        let body_len = u32::from_le_bytes([b[156], b[157], b[158], b[159]]);

        // salt_Q 区全 0xFF => 无保护问题
        let salt_q_bytes = &b[32..48];
        let has_q = !salt_q_bytes.iter().all(|x| *x == 0xFF);
        let (salt_q, wrapped_mk_q, question) = if has_q {
            let mut sq = [0u8; 16];
            sq.copy_from_slice(salt_q_bytes);
            let mut wq = [0u8; 48];
            wq.copy_from_slice(&b[108..156]);
            // 预留区问题文本：0xAC 处 1B 长度 + UTF-8
            let qlen = b[RESERVED_OFF] as usize;
            if qlen > QUESTION_MAX_LEN || RESERVED_OFF + 1 + qlen > HEADER_LEN {
                return Err(CryptoError::CorruptHeader);
            }
            let qtext = if qlen > 0 {
                match std::str::from_utf8(&b[RESERVED_OFF + 1..RESERVED_OFF + 1 + qlen]) {
                    Ok(s) => Some(s.to_string()),
                    Err(_) => return Err(CryptoError::CorruptHeader),
                }
            } else {
                None
            };
            (Some(sq), Some(wq), qtext)
        } else {
            (None, None, None)
        };

        Ok(VaultHeader {
            kdf,
            salt1,
            salt_q,
            nonce_kek,
            wrapped_mk,
            wrapped_mk_q,
            body_len,
            nonce_body,
            flags,
            question,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kdf::KdfParams;

    fn sample_header() -> VaultHeader {
        let mut h = VaultHeader::fresh();
        h.kdf = KdfParams::password_default();
        h.salt1 = [1u8; 16];
        h.salt_q = Some([2u8; 16]);
        h.nonce_kek = [3u8; 12];
        h.wrapped_mk = [4u8; 48];
        h.wrapped_mk_q = Some([5u8; 48]);
        h.body_len = 1234;
        h.nonce_body = [6u8; 12];
        h.flags = FLAG_ITEM_ENC;
        h.question = Some("我的第一个宠物叫什么？".to_string());
        h
    }

    #[test]
    fn golden_byte_positions() {
        // 黄金布局测试：关键字段必须出现在 §4.5 精确偏移
        let h = sample_header();
        let b = h.to_bytes();
        assert_eq!(&b[0..8], b"VLTB0X01");
        assert_eq!(&b[8..10], &[0x00, 0x01]); // header_len = 0x0100 LE
        assert_eq!(b[10], 0x01); // kdf_alg
        assert_eq!(&b[11..14], &[64, 3, 1]); // kdf 64/3/1
        assert_eq!(b[14], 0x01); // cipher_alg
        assert_eq!(b[15], FLAG_ITEM_ENC);
        assert_eq!(&b[16..32], &[1u8; 16]); // salt1
        assert_eq!(&b[32..48], &[2u8; 16]); // salt_q
        assert_eq!(&b[48..60], &[3u8; 12]); // nonce_kek
        assert_eq!(&b[60..108], &[4u8; 48]); // wrapped_mk
        assert_eq!(&b[108..156], &[5u8; 48]); // wrapped_mk_q
        assert_eq!(&b[156..160], &(1234u32).to_le_bytes()); // body_len
        assert_eq!(&b[160..172], &[6u8; 12]); // nonce_body
        let q = h.question.as_ref().unwrap();
        assert_eq!(b[RESERVED_OFF] as usize, q.len());
        assert_eq!(&b[RESERVED_OFF + 1..RESERVED_OFF + 1 + q.len()], q.as_bytes());
        // 头长度固定
        assert_eq!(b.len(), HEADER_LEN);
    }

    #[test]
    fn from_bytes_roundtrip() {
        let h = sample_header();
        let b = h.to_bytes();
        let h2 = VaultHeader::from_bytes(&b).unwrap();
        // 字段级一致（随机预留区不影响字段）
        assert_eq!(h, h2);
        assert_eq!(h2.question.as_deref(), Some("我的第一个宠物叫什么？"));
    }

    #[test]
    fn no_question_marks_all_ff() {
        let mut h = VaultHeader::fresh();
        h.salt_q = None;
        h.wrapped_mk_q = None;
        h.question = None;
        h.salt1 = [7u8; 16];
        let b = h.to_bytes();
        assert_eq!(&b[32..48], &[0xFFu8; 16]);
        let h2 = VaultHeader::from_bytes(&b).unwrap();
        assert_eq!(h2.salt_q, None);
        assert_eq!(h2.wrapped_mk_q, None);
        assert_eq!(h2.question, None);
        assert_eq!(h2.salt1, [7u8; 16]);
    }

    #[test]
    fn from_bytes_rejects_tamper() {
        let h = sample_header();
        let b = h.to_bytes();
        // 魔数破坏
        let mut bad = b.clone();
        bad[0] ^= 0xFF;
        assert!(matches!(
            VaultHeader::from_bytes(&bad),
            Err(CryptoError::CorruptHeader)
        ));
        // 短输入
        assert!(VaultHeader::from_bytes(&b[..100]).is_err());
        // kdf 参数越界 -> corrupt
        bad = b.clone();
        bad[11] = 1;
        assert!(VaultHeader::from_bytes(&bad).is_err());
        // cipher_alg 变化
        bad = b.clone();
        bad[14] = 9;
        assert!(matches!(
            VaultHeader::from_bytes(&bad),
            Err(CryptoError::UnsupportedVersion)
        ));
        // 问题文本区长度字节被改大 -> corrupt
        bad = b.clone();
        bad[RESERVED_OFF] = 90;
        assert!(matches!(
            VaultHeader::from_bytes(&bad),
            Err(CryptoError::CorruptHeader)
        ));
    }

    #[test]
    fn to_bytes_reserved_random_each_call() {
        // 两次 to_bytes 预留区不同（伪装随机），但解析回字段不变
        let h = sample_header();
        let b1 = h.to_bytes();
        let b2 = h.to_bytes();
        let h1 = VaultHeader::from_bytes(&b1).unwrap();
        let h2 = VaultHeader::from_bytes(&b2).unwrap();
        assert_eq!(h1, h2);
        assert_ne!(&b1[RESERVED_OFF + 14..], &b2[RESERVED_OFF + 14..]);
    }

    #[test]
    fn aad_mk_is_first_0x3c_bytes() {
        let h = sample_header();
        let b = h.to_bytes();
        assert_eq!(&h.aad_mk()[..], &b[..0x3C]);
        // aad 不含 wrapped_mk 本身
        let mut h2 = h.clone();
        h2.wrapped_mk = [9u8; 48];
        assert_eq!(h.aad_mk(), h2.aad_mk());
    }
}
