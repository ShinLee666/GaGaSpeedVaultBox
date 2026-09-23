//! 容器读写（CONTRACT §5 vault/container.rs；设计 §4.5 / T1.5 / T2.4）。
//!
//! 文件布局（本 crate 自洽定义，详见 header.rs 顶部注释）：
//! ```text
//! 0x000 .. 0x100   头部 256B（VaultHeader::to_bytes，AAD 计算所需）
//! 0x100 .. EOF     密文段 = aead seal 完整输出 nonce(12)||ct||tag(16)
//! ```
//! - `header.body_len` = 密文段总长；`header.nonce_body` = 密文段前 12B 镜像，
//!   打开时校验两者与文件长度，任何不一致判 Corrupt。
//! - 明文载荷（body 解密后）= `2B qlen(LE u16) + q_utf8 + sqlite 库字节`
//!   （qlen = 0 表示无保护问题；CONTRACT §5 约定）。问题文本同时在头部预留区
//!   存一份（<=80B，供"忘记密码"在不解锁时显示）。
//! - 每次保存（rewrite / repack / rewrap）整体重建密文段并刷新 nonce；
//!   改密（repack / rewrap）额外刷新 salt1 / nonce_kek / wrapped_MK。
//!
//! 写安全（设计 §4.5）：tmp 写入 -> fsync -> 滚动 .bak1/.bak2 -> 原子 rename。
//!
//! 错误分类（设计 §4.5 / T1.5）：头部解析失败 -> Corrupt；解 wrapped_MK
//! 认证失败 -> WrongPassword；解 body 失败（MK 正确但密文被改/半写）-> Corrupt。

use std::fs::{self, File};
use std::io::Write as _;
use std::path::Path;

use crate::crypto::aead;
use crate::crypto::derive::data_key;
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::secret::{fill_random, key32_from_slice, random_key32, Key32, SecretBytes};
use crate::crypto::CryptoError;
use crate::error::VaultError;

use super::header::{VaultHeader, HEADER_LEN, QUESTION_MAX_LEN};

/// 问题文本（UTF-8 字节数）上限：需同时满足"头部预留区存储"。
pub const QUESTION_TEXT_MAX_BYTES: usize = QUESTION_MAX_LEN;

// ---------------------------------------------------------------------------
// 对外接口（CONTRACT §5 要求签名）
// ---------------------------------------------------------------------------

/// 新建并保存容器。db_bytes = 内存库 serialize 出的明文库字节。
/// question = (问题文本, 答案原始字节)，两者同有同无；问题文本 <= 80B。
/// 若 path 已存在返回 AlreadyExists（初始化逻辑在调用方已先判）。
pub fn create_vault(
    path: &Path,
    password: &[u8],
    db_bytes: &[u8],
    question: Option<(&str, &[u8])>,
) -> Result<(), VaultError> {
    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    if password.is_empty() {
        return Err(VaultError::BadRequest("密码不能为空".to_string()));
    }
    // 校验问题文本约束（<=80B 且非空）
    if let Some((q, ans)) = &question {
        if q.trim().is_empty() {
            return Err(VaultError::BadRequest(
                "保护问题不能为空".to_string(),
            ));
        }
        if q.len() > QUESTION_TEXT_MAX_BYTES {
            return Err(VaultError::BadRequest(format!(
                "保护问题过长（最多 {QUESTION_TEXT_MAX_BYTES} 字节）"
            )));
        }
        if ans.is_empty() {
            return Err(VaultError::BadRequest(
                "保护问题答案不能为空".to_string(),
            ));
        }
    }

    let mut hdr = VaultHeader::fresh();
    hdr.kdf = KdfParams::password_default();
    fill_random(&mut hdr.salt1);

    // 1) MK 随机；KEK = Argon2id(password, salt1)；wrapped_MK 先行（AAD 不含自身）
    let mk = random_key32();
    let kek = kdf::derive_key(password, &hdr.salt1, &hdr.kdf)?;

    // 2) 保护问题路径（KEK_Q 成本加档：answer_default）
    if let Some((q_text, answer)) = &question {
        let mut salt_q = [0u8; 16];
        fill_random(&mut salt_q);
        hdr.salt_q = Some(salt_q);
        hdr.question = Some(q_text.to_string());
        let kek_q = kdf::derive_key(answer, &salt_q, &KdfParams::answer_default())?;
        fill_random(&mut hdr.nonce_kek);
        hdr.wrapped_mk = wrap_mk(&kek, &hdr.nonce_kek, &mk, &hdr)?;
        hdr.wrapped_mk_q = Some(wrap_mk(&kek_q, &hdr.nonce_kek, &mk, &hdr)?);
    } else {
        fill_random(&mut hdr.nonce_kek);
        hdr.wrapped_mk = wrap_mk(&kek, &hdr.nonce_kek, &mk, &hdr)?;
    }

    // 3) DK = HKDF(MK)；明文载荷 = 2B qlen + q_utf8 + db；整段加密
    let dk = data_key(&mk);
    let payload = payload_build(question.map(|(q, _)| q), db_bytes);
    finish_body_and_write(path, &mut hdr, &dk, &payload)
}

/// 解锁容器（仅返回解出的明文库字节与问题文本，不返回密钥材料）。
/// 返回 (头部, 明文库字节, 问题文本)。供 check / 只读场景使用。
pub fn open_vault(
    path: &Path,
    password: &[u8],
) -> Result<(VaultHeader, SecretBytes, Option<String>), VaultError> {
    let (hdr, _mk, _dk, db, question) = unlock_vault(path, password)?;
    Ok((hdr, db, question))
}

/// 解锁容器（完整版）：额外返回 MK 与 DK（供保存 / 改密等后续操作复用，
/// 会话层 Session 持有的就是这两个值）。命令层 / CLI 均走本函数。
pub fn unlock_vault(
    path: &Path,
    password: &[u8],
) -> Result<(VaultHeader, Key32, Key32, SecretBytes, Option<String>), VaultError> {
    let data = read_all(path)?;
    let hdr = parse_header(&data)?;
    let body_len = hdr.body_len as usize;
    if body_len < 28 {
        return Err(VaultError::Corrupt);
    }
    if data.len() != HEADER_LEN + body_len {
        return Err(VaultError::Corrupt);
    }
    let blob = &data[HEADER_LEN..];
    if blob.len() < 12 || blob[..12] != hdr.nonce_body {
        return Err(VaultError::Corrupt);
    }

    // 密码校验 = 解 wrapped_MK（GCM tag 过即密码正确，见设计 §4.3）
    let kek = kdf::derive_key(password, &hdr.salt1, &hdr.kdf)?;
    let aad_mk = hdr.aad_mk();
    let mk_bytes = aead::open_with_nonce(&kek, &hdr.nonce_kek, &hdr.wrapped_mk, &aad_mk)
        .map_err(|e| match e {
            // 认证失败 => 密码错误（与"文件损坏"统一文案防探测）
            CryptoError::DecryptFailed => VaultError::WrongPassword,
            other => VaultError::Crypto(other),
        })?;
    let mk = key32_from_slice(&mk_bytes).ok_or(VaultError::Corrupt)?;
    let dk = data_key(&mk);

    // body 解密失败（MK 正确但 body 错）=> 文件损坏/被篡改
    let payload = aead::open(&dk, blob, &data[..HEADER_LEN])
        .map_err(|_| VaultError::Corrupt)?;
    let (_q, db_bytes) = payload_split(&payload)?;
    let db = SecretBytes::new(db_bytes.to_vec());
    let question = hdr.question.clone();
    Ok((hdr, mk, dk, db, question))
}

/// 保存（flush）：全量重建密文段并刷新 body nonce（盐/nonce 中凡涉及
/// KEK 派生的区段——salt1 / nonce_kek / wrapped_MK——保持不变：内存中仅
/// 持有 MK/DK 而无口令，无法重派生 KEK；MK 终身不变故 wrapped_MK 无需更新，
/// 每次保存的"新鲜密文"体现在整体重建的 body 上。改密才走 repack/rewrap）。
/// header 参数为当前容器解析结果（保存前由调用方 read_header 或解锁时取得）。
pub fn rewrite_vault(
    path: &Path,
    header: &VaultHeader,
    mk: &Key32,
    db_bytes: &[u8],
) -> Result<(), VaultError> {
    let dk = data_key(mk);
    let payload = payload_build(header.question.as_deref(), db_bytes);
    let mut hdr = header.clone();
    finish_body_and_write(path, &mut hdr, &dk, &payload)
}

/// 重包 MK（忘记密码重置 / 主动改密共用，CONTRACT §5）。
/// mk 由调用方经"答案解开 wrapped_MK_Q"或"当前密码解开 wrapped_MK"获得。
/// new_question = Some 则以新问题+新答案重建问题路径；None 则清除问题路径
/// （salt_Q 区置 0xFF、wrapped_MK_Q 与问题文本一并作废）。
/// 整体重写文件：salt1 / nonce_kek / wrapped 全刷新，body 不解密不行——
/// body 的 AAD 是整段头部，头部任何字节变化都要求 body 用新 AAD 重加密，
/// 故此处用 mk 派 DK 先解旧 body 取库字节，再按新头部重加密。
pub fn repack_mk(
    path: &Path,
    mk: &Key32,
    new_password: &[u8],
    new_question: Option<(&str, &[u8])>,
) -> Result<(), VaultError> {
    if new_password.is_empty() {
        return Err(VaultError::BadRequest("新密码不能为空".to_string()));
    }
    if let Some((q, ans)) = &new_question {
        if q.trim().is_empty() || ans.is_empty() {
            return Err(VaultError::BadRequest(
                "保护问题与答案不能为空".to_string(),
            ));
        }
        if q.len() > QUESTION_TEXT_MAX_BYTES {
            return Err(VaultError::BadRequest(format!(
                "保护问题过长（最多 {QUESTION_TEXT_MAX_BYTES} 字节）"
            )));
        }
    }

    let data = read_all(path)?;
    let old_hdr = parse_header(&data)?;
    // 解旧 body 取出库字节（新头部 AAD 变化，body 必须重加密）
    let dk_old = data_key(mk);
    let payload_old = aead::open(&dk_old, &data[HEADER_LEN..], &data[..HEADER_LEN])
        .map_err(|_| VaultError::Corrupt)?;
    let (_old_q, db_bytes) = payload_split(&payload_old)?;

    // 组装新头部（保留容器 kdf 档位；密码新盐 + 新 nonce）
    let mut hdr = VaultHeader::fresh();
    hdr.kdf = old_hdr.kdf; // 参数随容器保存；换密码不升级参数
    hdr.flags = old_hdr.flags;
    fill_random(&mut hdr.salt1);
    let kek = kdf::derive_key(new_password, &hdr.salt1, &hdr.kdf)?;

    let mut payload_q: Option<&str> = None;
    if let Some((q_text, answer)) = &new_question {
        let mut salt_q = [0u8; 16];
        fill_random(&mut salt_q);
        hdr.salt_q = Some(salt_q);
        hdr.question = Some(q_text.to_string());
        let kek_q = kdf::derive_key(answer, &salt_q, &KdfParams::answer_default())?;
        fill_random(&mut hdr.nonce_kek);
        hdr.wrapped_mk = wrap_mk(&kek, &hdr.nonce_kek, mk, &hdr)?;
        hdr.wrapped_mk_q = Some(wrap_mk(&kek_q, &hdr.nonce_kek, mk, &hdr)?);
        payload_q = Some(q_text);
    } else {
        fill_random(&mut hdr.nonce_kek);
        hdr.wrapped_mk = wrap_mk(&kek, &hdr.nonce_kek, mk, &hdr)?;
    }

    let dk = data_key(mk);
    let payload = payload_build(payload_q, db_bytes);
    finish_body_and_write(path, &mut hdr, &dk, &payload)
}

/// 仅重包密码路径、保留既有保护问题（主动改密 change_password 用）。
/// 说明：nonce_kek 必须保持原值——wrapped_MK_Q 由 KEK_Q 在创建时以同一
/// nonce 加密，会话中无答案无法重加密它；新 KEK 与旧 KEK 不同，同 nonce
/// 加密不同密钥不构成 nonce 重用风险。
pub fn rewrap_password(
    path: &Path,
    mk: &Key32,
    db_bytes: &[u8],
    new_password: &[u8],
) -> Result<(), VaultError> {
    if new_password.is_empty() {
        return Err(VaultError::BadRequest("新密码不能为空".to_string()));
    }
    let data = read_all(path)?;
    let old_hdr = parse_header(&data)?;

    let mut hdr = old_hdr.clone(); // salt_q / wrapped_mk_q / question / nonce_kek 原样保留
    fill_random(&mut hdr.salt1);
    hdr.wrapped_mk_q = old_hdr.wrapped_mk_q;
    let kek = kdf::derive_key(new_password, &hdr.salt1, &hdr.kdf)?;
    hdr.wrapped_mk = wrap_mk(&kek, &hdr.nonce_kek, mk, &hdr)?;

    let dk = data_key(mk);
    let payload = payload_build(old_hdr.question.as_deref(), db_bytes);
    finish_body_and_write(path, &mut hdr, &dk, &payload)
}

/// 仅解析并返回容器头部（不校验密码；"忘记密码"页显示问题文本用）。
pub fn read_header(path: &Path) -> Result<VaultHeader, VaultError> {
    let data = read_all(path)?;
    parse_header(&data)
}

// ---------------------------------------------------------------------------
// 内部实现
// ---------------------------------------------------------------------------

/// 用 KEK 包裹 MK：AAD = 头部前 0x3C 字节；输出 ct||tag 48B（nonce 单独存放）。
fn wrap_mk(kek: &Key32, nonce: &[u8; 12], mk: &Key32, hdr: &VaultHeader) -> Result<[u8; 48], VaultError> {
    let aad = hdr.aad_mk();
    let blob = aead::seal_with_nonce(kek, nonce, mk.as_ref(), &aad)?;
    debug_assert_eq!(blob.len(), 60, "wrapped 应为 nonce12+ct32+tag16");
    let mut out = [0u8; 48];
    out.copy_from_slice(&blob[12..]); // 去掉 nonce 前缀，仅存 ct||tag
    Ok(out)
}

/// 明文载荷编码：2B qlen(LE u16) + q_utf8 + sqlite 字节（qlen=0 表示无问题）。
fn payload_build(q: Option<&str>, db_bytes: &[u8]) -> Vec<u8> {
    let qbytes = q.unwrap_or("").as_bytes();
    let mut out = Vec::with_capacity(2 + qbytes.len() + db_bytes.len());
    out.extend_from_slice(&(qbytes.len() as u16).to_le_bytes());
    out.extend_from_slice(qbytes);
    out.extend_from_slice(db_bytes);
    out
}

/// 明文载荷解码：返回 (问题文本, 剩余 sqlite 库字节)。
fn payload_split(payload: &[u8]) -> Result<(Option<String>, &[u8]), VaultError> {
    if payload.len() < 2 {
        return Err(VaultError::Corrupt);
    }
    let qlen = u16::from_le_bytes([payload[0], payload[1]]) as usize;
    if 2 + qlen > payload.len() {
        return Err(VaultError::Corrupt);
    }
    let q = if qlen > 0 {
        let s = std::str::from_utf8(&payload[2..2 + qlen])
            .map_err(|_| VaultError::Corrupt)?;
        Some(s.to_string())
    } else {
        None
    };
    Ok((q, &payload[2 + qlen..]))
}

/// 组装最终容器：随机 nonce_body -> 序列化头部（一次性）-> 以头部为 AAD
/// 加密 payload -> 拼接写盘。
fn finish_body_and_write(
    path: &Path,
    hdr: &mut VaultHeader,
    dk: &Key32,
    payload: &[u8],
) -> Result<(), VaultError> {
    let blob_len = 28usize
        .checked_add(payload.len())
        .ok_or_else(|| VaultError::BadRequest("载荷过大".to_string()))?;
    if blob_len > u32::MAX as usize {
        return Err(VaultError::BadRequest("载荷过大".to_string()));
    }
    fill_random(&mut hdr.nonce_body);
    hdr.body_len = blob_len as u32;
    let header_bytes = hdr.to_bytes();
    // body 的 AAD = 实际写盘的整段头部字节
    let blob = aead::seal_with_nonce(dk, &hdr.nonce_body, payload, &header_bytes)?;
    debug_assert_eq!(blob.len(), blob_len);
    let mut file = Vec::with_capacity(HEADER_LEN + blob.len());
    file.extend_from_slice(&header_bytes);
    file.extend_from_slice(&blob);
    write_atomic(path, &file)
}

/// 读取整个容器文件（密文不敏感，普通 Vec 即可；错误分类：不存在 -> NotFound）。
fn read_all(path: &Path) -> Result<Vec<u8>, VaultError> {
    match fs::read(path) {
        Ok(v) => Ok(v),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(VaultError::NotFound)
        }
        Err(e) => Err(VaultError::Internal(format!("读取文件失败: {e}"))),
    }
}

/// 解析并校验头部（错误统一归类为 Corrupt / 版本不支持）。
fn parse_header(data: &[u8]) -> Result<VaultHeader, VaultError> {
    if data.len() < HEADER_LEN {
        return Err(VaultError::Corrupt);
    }
    VaultHeader::from_bytes(&data[..HEADER_LEN]).map_err(|_| VaultError::Corrupt)
}

/// 原子写 + 滚动备份（设计 §4.5：tmp -> fsync -> 滚动 .bak1/.bak2 -> rename）。
/// Windows 上 fs::rename 目标已存在会失败，因此滚动顺序：删 bak2 ->
/// bak1->bak2 -> 现文件->bak1 -> tmp->目标。
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let tmp = sibling_path(path, ".tmp");
    let bak1 = sibling_path(path, ".bak1");
    let bak2 = sibling_path(path, ".bak2");

    // 1) 写 tmp 并 fsync
    {
        let mut f = File::create(&tmp)
            .map_err(|e| VaultError::Internal(format!("创建临时文件失败: {e}")))?;
        f.write_all(data)
            .map_err(|e| VaultError::Internal(format!("写临时文件失败: {e}")))?;
        f.sync_all()
            .map_err(|e| VaultError::Internal(format!("fsync 失败: {e}")))?;
    }

    // 2) 滚动备份（目标存在才滚动）
    if path.exists() {
        if bak2.exists() {
            let _ = fs::remove_file(&bak2);
        }
        if bak1.exists() {
            fs::rename(&bak1, &bak2).map_err(|e| {
                VaultError::Internal(format!("滚动备份失败: {e}"))
            })?;
        }
        fs::rename(path, &bak1).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            VaultError::Internal(format!("备份当前文件失败: {e}"))
        })?;
    }

    // 3) 原子替换
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        VaultError::Internal(format!("替换文件失败: {e}"))
    })?;
    Ok(())
}

/// 生成形如 `<原名>.bak1` 的兄弟路径（保留原扩展名）。
fn sibling_path(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("vaultbox_test_{stamp}_{name}.vault"));
        p
    }

    fn make_db_bytes() -> Vec<u8> {
        // 用真实内存库产出的字节，保证与 db 模块兼容
        let conn = memory::open_empty().unwrap();
        conn.execute_batch(
            "INSERT INTO meta(key,value) VALUES('t','1');
             INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
             VALUES('u-1',x'00',x'01',0,1,2);",
        )
        .unwrap();
        memory::export_bytes(&conn).unwrap().to_vec()
    }

    const PW: &[u8] = b"Correct-Horse-9!";
    const ANS: &[u8] = b"my favorite pet is wangcai";

    #[test]
    fn create_open_roundtrip_with_question() {
        let path = tmp_path("roundtrip");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, Some(("我的第一个宠物叫什么？", ANS))).unwrap();
        let (hdr, out_db, q) = open_vault(&path, PW).unwrap();
        assert_eq!(out_db.as_slice(), db.as_slice());
        assert_eq!(q.as_deref(), Some("我的第一个宠物叫什么？"));
        assert!(hdr.salt_q.is_some());
        assert!(hdr.wrapped_mk_q.is_some());
        // 库字节里能查到测试行（证明与 db 模块互操作）
        let conn = memory::import_bytes(&out_db).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_password_rejected() {
        let path = tmp_path("wrongpw");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, Some(("问题？", ANS))).unwrap();
        let err = open_vault(&path, b"Wrong-Pass-999").unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword), "{err:?}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unlock_returns_mk_dk() {
        let path = tmp_path("unlock");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, None).unwrap();
        let (_h, mk, dk, out_db, q) = unlock_vault(&path, PW).unwrap();
        assert_eq!(out_db.as_slice(), db.as_slice());
        assert!(q.is_none());
        // mk/dk 能派生出一致 ITEM_KEY 链路（后续条目加解密依赖）
        let _ = crate::crypto::derive::item_key(&dk, &[1u8; 16]);
        assert_eq!(mk.len(), 32);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn tamper_regression() {
        let path = tmp_path("tamper");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, None).unwrap();

        // 1) 篡改 body 任一字节 -> Corrupt（MK 对但 body 错）
        let mut data = fs::read(&path).unwrap();
        let pos = data.len() - 3;
        data[pos] ^= 0x01;
        fs::write(&path, &data).unwrap();
        let err = open_vault(&path, PW).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt), "body 篡改应 Corrupt: {err:?}");

        // 2) 篡改 wrapped_MK 任一字节 -> WrongPassword（认证失败）
        let mut data = fs::read(&path).unwrap();
        data[0x3C + 5] ^= 0x01;
        fs::write(&path, &data).unwrap();
        let err = open_vault(&path, PW).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword), "wrapped_MK 篡改应 WrongPassword: {err:?}");

        // 3) 篡改 MAGIC -> Corrupt
        let mut data = fs::read(&path).unwrap();
        data[0] ^= 0xFF;
        fs::write(&path, &data).unwrap();
        let err = open_vault(&path, PW).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt), "魔数篡改应 Corrupt: {err:?}");

        // 4) 截断文件 -> Corrupt
        let mut data = fs::read(&path).unwrap();
        data.truncate(data.len() - 4);
        fs::write(&path, &data).unwrap();
        let err = open_vault(&path, PW).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rewrite_vault_flush_preserves_password() {
        let path = tmp_path("rewrite");
        let db1 = make_db_bytes();
        create_vault(&path, PW, &db1, Some(("问题？", ANS))).unwrap();
        let (hdr, mk, _dk, _old, q) = unlock_vault(&path, PW).unwrap();
        assert_eq!(q.as_deref(), Some("问题？"));
        // 模拟新增内容后的 flush
        let db2 = make_db_bytes();
        rewrite_vault(&path, &hdr, &mk, &db2).unwrap();
        let (_h, out, _) = open_vault(&path, PW).unwrap();
        assert_eq!(out.as_slice(), db2.as_slice());
        // 刷新后仍能正确回答旧问题（wrapped_MK_Q 未受影响）
        let (_h2, mk2, _dk2, db2_out, q2) = unlock_vault(&path, PW).unwrap();
        assert_eq!(mk.as_ref(), mk2.as_ref());
        assert_eq!(db2_out.as_slice(), db2.as_slice());
        assert_eq!(q2.as_deref(), Some("问题？"));
        // 备份滚动：至少 .bak1 存在
        assert!(sibling_path(&path, ".bak1").exists());
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(sibling_path(&path, ".bak1"));
    }

    #[test]
    fn repack_mk_reset_drops_question() {
        let path = tmp_path("repack");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, Some(("问题？", ANS))).unwrap();
        // 忘记密码真实路径：读头部 -> 答案解 wrapped_MK_Q 得 mk -> repack_mk
        let data = fs::read(&path).unwrap();
        let hdr = parse_header(&data).unwrap();
        let salt_q = hdr.salt_q.expect("应有答案盐");
        let kek_q = kdf::derive_key(ANS, &salt_q, &KdfParams::answer_default()).unwrap();
        let aad = hdr.aad_mk();
        let mk_bytes = aead::open_with_nonce(&kek_q, &hdr.nonce_kek, hdr.wrapped_mk_q.as_ref().unwrap(), &aad).unwrap();
        let mk = key32_from_slice(&mk_bytes).unwrap();

        repack_mk(&path, &mk, b"New-Pass-123!", None).unwrap();
        // 新密码可开
        let (_h, out, q) = open_vault(&path, b"New-Pass-123!").unwrap();
        assert_eq!(out.as_slice(), db.as_slice());
        assert!(q.is_none(), "重置应清除问题");
        // 旧密码失效
        let err = open_vault(&path, PW).unwrap_err();
        assert!(matches!(err, VaultError::WrongPassword));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rewrap_password_keeps_question() {
        let path = tmp_path("rewrap");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, Some(("问题？", ANS))).unwrap();
        // change_password：会话持有 mk，直接重包
        let (_h, mk, _dk, _db, _q) = unlock_vault(&path, PW).unwrap();
        rewrap_password(&path, &mk, &db, b"Changed-Pass-456").unwrap();
        let (_h2, out, q2) = open_vault(&path, b"Changed-Pass-456").unwrap();
        assert_eq!(out.as_slice(), db.as_slice());
        assert_eq!(q2.as_deref(), Some("问题？"), "改密应保留问题");
        // 旧密码失效
        assert!(matches!(
            open_vault(&path, PW).unwrap_err(),
            VaultError::WrongPassword
        ));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn create_rejects_existing_and_long_question() {
        let path = tmp_path("exists");
        let db = make_db_bytes();
        create_vault(&path, PW, &db, None).unwrap();
        let err = create_vault(&path, PW, &db, None).unwrap_err();
        assert!(matches!(err, VaultError::AlreadyExists));
        let _ = fs::remove_file(&path);

        // 超长问题
        let path2 = tmp_path("longq");
        let long_q = "超".repeat(QUESTION_TEXT_MAX_BYTES + 1);
        let err = create_vault(&path2, PW, &db, Some((&long_q, ANS))).unwrap_err();
        assert!(matches!(err, VaultError::BadRequest(_)));
        assert!(!path2.exists());
    }

    #[test]
    fn missing_file_is_not_found() {
        let err = open_vault(Path::new("Z:/definitely/not/exists.vault"), PW).unwrap_err();
        assert!(matches!(err, VaultError::NotFound), "{err:?}");
    }

    #[test]
    fn unicode_db_roundtrip() {
        // 中文条目内容全链路无损
        let path = tmp_path("unicode");
        let conn = memory::open_empty().unwrap();
        conn.execute_batch(
            "INSERT INTO meta(key,value) VALUES('k','值');
             INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
             VALUES('id-中文',x'00',x'01',0,1,2);",
        )
        .unwrap();
        let db = memory::export_bytes(&conn).unwrap().to_vec();
        create_vault(&path, PW, &db, Some(("我的宠物？", ANS))).unwrap();
        let (_h, out, q) = open_vault(&path, PW).unwrap();
        assert_eq!(q.as_deref(), Some("我的宠物？"));
        let c2 = memory::import_bytes(&out).unwrap();
        let v: String = c2
            .query_row("SELECT value FROM meta WHERE key='k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "值");
        let _ = fs::remove_file(&path);
    }
}
