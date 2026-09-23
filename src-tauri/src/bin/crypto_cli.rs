//! VaultBox 自检 CLI（CONTRACT §5 bin/crypto_cli.rs；设计 T1.7）。
//!
//! 用途：GUI 之前的垂直切片 + 黄金向量生成 + 完整性自检。CLI 直通真实
//! 代码路径（crypto/vault/db 同一套模块），GUI 只是换一层壳。
//!
//! 子命令：
//! ```text
//! crypto_cli init  <path> -p <密码> [-q <问题> -a <答案>]
//! crypto_cli add   <path> -p <密码> -t <标题> -c <内容> [-n <备注>] [-k 0|1|2]
//! crypto_cli list  <path> -p <密码>
//! crypto_cli check <path> -p <密码>
//! crypto_cli reset <path> -a <答案> -p <新密码>
//! crypto_cli selftest
//! crypto_cli gen-vectors <输出目录>
//! ```
//!
//! 注意：本 CLI 面向自动化验证，密码经命令行参数传入（进程列表可见），
//! 仅限开发/自检使用；GUI 生产路径口令只存在于内存。

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use vaultbox_core::crypto::aead;
use vaultbox_core::crypto::derive::data_key;
use vaultbox_core::crypto::kdf::{self, KdfParams};
use vaultbox_core::crypto::secret::{random_key32, Key32};
use vaultbox_core::db::{memory, rows};
use vaultbox_core::error::VaultError;
use vaultbox_core::util::{normalize_answer, now_ms, validate_answer, validate_password};
use vaultbox_core::vault::container;
use vaultbox_core::vault::header::VaultHeader;
use vaultbox_core::vault::item::{self, kind_name};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return ExitCode::from(2);
    }
    let cmd = args[0].as_str();
    let rest = &args[1..];
    let result = match cmd {
        "init" => cmd_init(rest),
        "add" => cmd_add(rest),
        "list" => cmd_list(rest),
        "check" => cmd_check(rest),
        "reset" => cmd_reset(rest),
        "selftest" => cmd_selftest(),
        "gen-vectors" => cmd_gen_vectors(rest),
        "-h" | "--help" | "help" => {
            print_usage();
            return ExitCode::SUCCESS;
        }
        other => {
            eprintln!("未知子命令: {other}");
            print_usage();
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            // 按错误契约输出 code + message（与 GUI 相同的映射口径）
            eprintln!("[{}] {}", e.code(), e);
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "VaultBox crypto_cli（自检 / 黄金向量 / 垂直切片）\n\
         \n\
         用法:\n\
         \x20 crypto_cli init  <path> -p <密码> [-q <问题> -a <答案>]\n\
         \x20 crypto_cli add   <path> -p <密码> -t <标题> -c <内容> [-n <备注>] [-k 0|1|2]\n\
         \x20 crypto_cli list  <path> -p <密码>\n\
         \x20 crypto_cli check <path> -p <密码>\n\
         \x20 crypto_cli reset <path> -a <答案> -p <新密码>\n\
         \x20 crypto_cli selftest\n\
         \x20 crypto_cli gen-vectors <输出目录>"
    );
}

// ---------------------------------------------------------------------------
// 参数解析小工具
// ---------------------------------------------------------------------------

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn require<'a>(args: &'a [String], flag: &str, usage: &str) -> Result<&'a str, VaultError> {
    arg_value(args, flag).ok_or_else(|| {
        VaultError::BadRequest(format!("缺少参数 {flag}。用法: {usage}"))
    })
}

fn path_arg(args: &[String], usage: &str) -> Result<PathBuf, VaultError> {
    args.first()
        .map(PathBuf::from)
        .ok_or_else(|| VaultError::BadRequest(format!("缺少路径参数。用法: {usage}")))
}

// ---------------------------------------------------------------------------
// init：建库 -> 建容器 -> 解锁 -> 写欢迎条目 -> 保存
// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli init <path> -p <密码> [-q <问题> -a <答案>]";
    let path = path_arg(args, usage)?;
    let password = require(args, "-p", usage)?;
    validate_password(password)?;

    let question = arg_value(args, "-q");
    let answer_raw = arg_value(args, "-a");
    let (question_text, answer_norm) = match (question, answer_raw) {
        (Some(q), Some(a)) => {
            let a_norm = normalize_answer(a);
            validate_answer(&a_norm, password)?;
            (Some(q.to_string()), Some(a_norm))
        }
        (None, None) => (None, None),
        _ => {
            return Err(VaultError::BadRequest(format!(
                "保护问题与答案必须同有同无。用法: {usage}"
            )))
        }
    };

    if path.exists() {
        return Err(VaultError::AlreadyExists);
    }
    // 目录不存在则创建
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // 1) 建内存库并写入元信息
    let conn = memory::open_empty()?;
    let ts = now_ms();
    memory::meta_set(&conn, "schema_version", "1")?;
    memory::meta_set(&conn, "created_at", &ts.to_string())?;
    memory::meta_set(&conn, "last_saved_at", &ts.to_string())?;
    let db1 = memory::export_bytes(&conn)?;

    // 2) 建容器（答案已规范化）
    let q_ref = question_text.as_deref();
    let ans_ref: Option<&[u8]> = answer_norm.as_deref().map(|s| s.as_bytes());
    let q_pair: Option<(&str, &[u8])> = match (q_ref, ans_ref) {
        (Some(q), Some(a)) => Some((q, a)),
        _ => None,
    };
    container::create_vault(&path, password.as_bytes(), &db1, q_pair)?;

    // 3) 解锁 -> 写欢迎条目 -> flush（走 rewrite_vault 保存路径）
    let (hdr, mk, dk, db_bytes, _q) = container::unlock_vault(&path, password.as_bytes())?;
    let conn2 = memory::import_bytes(&db_bytes)?;
    let welcome = format!(
        "欢迎使用 VaultBox！本保险箱创建于 {}。\n\
         此条目为系统自动生成的欢迎信息，可以删除。",
        ts
    );
    add_item_row(&conn2, &dk, item::KIND_NOTE, "欢迎使用 VaultBox", &welcome, None, &ts)?;
    memory::meta_set(&conn2, "last_saved_at", &now_ms().to_string())?;
    let db2 = memory::export_bytes(&conn2)?;
    container::rewrite_vault(&path, &hdr, &mk, &db2)?;

    // 断言头信息自洽（防静默写坏）
    let _ = VaultHeader::from_bytes(&hdr.to_bytes()).map_err(|_| VaultError::Corrupt)?;
    Ok(format!("初始化成功: {}", path.display()))
}

// ---------------------------------------------------------------------------
// add：解锁 -> 插入条目 -> flush
// ---------------------------------------------------------------------------

fn cmd_add(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli add <path> -p <密码> -t <标题> -c <内容> [-n <备注>] [-k 0|1|2]";
    let path = path_arg(args, usage)?;
    let password = require(args, "-p", usage)?;
    let title = require(args, "-t", usage)?;
    let content = require(args, "-c", usage)?;
    let note = arg_value(args, "-n");
    let kind: u8 = match arg_value(args, "-k") {
        Some(k) => k.parse().unwrap_or(255),
        None => item::KIND_ACCOUNT,
    };
    if kind > 2 {
        return Err(VaultError::BadRequest(
            "kind 必须为 0(账号)/1(备注)/2(密钥)".to_string(),
        ));
    }

    let (hdr, mk, dk, db_bytes, _q) = container::unlock_vault(&path, password.as_bytes())?;
    let conn = memory::import_bytes(&db_bytes)?;
    let ts = now_ms();
    let id = add_item_row(&conn, &dk, kind, title, content, note, &ts)?;
    let db2 = memory::export_bytes(&conn)?;
    container::rewrite_vault(&path, &hdr, &mk, &db2)?;
    Ok(format!("已添加条目 id={id} (kind={}, 标题={})", kind_name(kind), title))
}

/// 构造并插入一条密文条目（id 由 uuid v4 生成），返回 id。
fn add_item_row(
    conn: &rusqlite::Connection,
    dk: &Key32,
    kind: u8,
    title: &str,
    content: &str,
    note: Option<&str>,
    ts: &u64,
) -> Result<String, VaultError> {
    let id = uuid::Uuid::new_v4().to_string();
    let (salt, blob) =
        item::encrypt_item(dk, &id, kind, title, content, note).map_err(VaultError::Crypto)?;
    rows::insert(conn, &id, kind, &salt, &blob, *ts, *ts)?;
    Ok(id)
}

// ---------------------------------------------------------------------------
// list：解锁 -> 逐条解密标题
// ---------------------------------------------------------------------------

fn cmd_list(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli list <path> -p <密码>";
    let path = path_arg(args, usage)?;
    let password = require(args, "-p", usage)?;

    let (_hdr, _mk, dk, db_bytes, _q) = container::unlock_vault(&path, password.as_bytes())?;
    let conn = memory::import_bytes(&db_bytes)?;
    let all = rows::load_all(&conn)?;
    let mut out = String::new();
    out.push_str(&format!("共 {} 条条目:\n", all.len()));
    for r in &all {
        let title = match item::decrypt_item(&dk, &r.id, &r.salt, &r.blob) {
            Ok(p) => p.title,
            Err(_) => "<解密失败>".to_string(),
        };
        out.push_str(&format!(
            "  id={}  kind={}({})  updated_at={}  title={}\n",
            r.id,
            r.kind,
            kind_name(r.kind),
            r.updated_at,
            title
        ));
    }
    Ok(out.trim_end().to_string())
}

// ---------------------------------------------------------------------------
// check：完整性 / 认证自检
// ---------------------------------------------------------------------------

fn cmd_check(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli check <path> -p <密码>";
    let path = path_arg(args, usage)?;
    let password = require(args, "-p", usage)?;

    // 完整走一遍"读文件 -> 头解析 -> KEK -> MK -> DK -> body 解密"
    let (hdr, db_bytes, q) = container::open_vault(&path, password.as_bytes())?;
    // 头自洽校验
    let raw = std::fs::read(&path)?;
    if raw.len() != vaultbox_core::vault::header::HEADER_LEN + hdr.body_len as usize {
        return Err(VaultError::Corrupt);
    }
    let has_q = hdr.salt_q.is_some();
    Ok(format!(
        "完整性自检通过 ✓\n\
         \x20 文件: {}\n\
         \x20 文件大小: {} 字节 (头部 256B + 密文段 {}B)\n\
         \x20 KDF: Argon2id m={}MiB t={} p={}\n\
         \x20 保护问题: {}\n\
         \x20 明文库: {} 字节\n\
         \x20 问题文本: {}",
        path.display(),
        raw.len(),
        hdr.body_len,
        hdr.kdf.m_cost,
        hdr.kdf.t_cost,
        hdr.kdf.p_cost,
        if has_q { "已设置" } else { "未设置" },
        db_bytes.len(),
        q.unwrap_or_default(),
    ))
}

// ---------------------------------------------------------------------------
// reset：忘记密码（答案 -> MK -> 重包新密码，清除问题）
// ---------------------------------------------------------------------------

fn cmd_reset(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli reset <path> -a <答案> -p <新密码>";
    let path = path_arg(args, usage)?;
    let answer = require(args, "-a", usage)?;
    let new_password = require(args, "-p", usage)?;
    validate_password(new_password)?;
    let answer_norm = normalize_answer(answer);

    // 读头部 -> 答案档派生 KEK_Q（成本加档）-> 解 wrapped_MK_Q
    let hdr = container::read_header(&path)?;
    let salt_q = hdr
        .salt_q
        .ok_or_else(|| VaultError::BadRequest("该保险箱未设置保护问题，无法用答案重置".to_string()))?;
    let kek_q = kdf::derive_key(answer_norm.as_bytes(), &salt_q, &KdfParams::answer_default())?;
    let aad = hdr.aad_mk();
    let wrapped_q = hdr
        .wrapped_mk_q
        .as_ref()
        .ok_or(VaultError::Corrupt)?;
    let mk_bytes = aead::open_with_nonce(&kek_q, &hdr.nonce_kek, wrapped_q, &aad)
        .map_err(|_| VaultError::AnswerWrong)?;
    let mk = vaultbox_core::crypto::secret::key32_from_slice(&mk_bytes)
        .ok_or(VaultError::Corrupt)?;

    // 重包：新密码，问题一并清除（与 GUI recover_reset 语义一致）
    container::repack_mk(&path, &mk, new_password.as_bytes(), None)?;
    Ok("重置成功：已用新密码重包，保护问题已清除".to_string())
}

// ---------------------------------------------------------------------------
// selftest：黄金向量 + roundtrip + 篡改回归（运行时自检）
// ---------------------------------------------------------------------------

fn cmd_selftest() -> Result<String, VaultError> {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut check = |name: &str, ok: bool| {
        if ok {
            pass += 1;
            println!("  [PASS] {name}");
        } else {
            fail += 1;
            println!("  [FAIL] {name}");
        }
    };

    println!("VaultBox selftest（黄金向量 / roundtrip / 篡改回归）...");

    // 1) 黄金向量：Argon2id 交叉验证（m=32MiB 档；与 argon2-cffi/libargon2 比对一致）
    {
        let password: Vec<u8> = (1u8..=32).collect();
        let salt: Vec<u8> = (1u8..=16).collect();
        let p = KdfParams { m_cost: 32, t_cost: 3, p_cost: 4 };
        let got = kdf::derive_key(&password, &salt, &p).map(|k| hex::encode(k.as_ref()));
        check(
            "黄金向量 kdf/argon2id (libargon2 交叉验证)",
            got.as_deref() == Ok("4fa3bfb55e773b08dd080d6791d8999becbedae42633a1faab98ba6f7bd86b56"),
        );
    }

    // 2) HKDF 派生链路确定性
    {
        let mk = random_key32();
        let dk1 = data_key(&mk);
        let dk2 = data_key(&mk);
        check("derive/data_key 确定性", dk1.as_ref() == dk2.as_ref());
        let k1 = vaultbox_core::crypto::derive::item_key(&dk1, &[1u8; 16]);
        let k2 = vaultbox_core::crypto::derive::item_key(&dk1, &[2u8; 16]);
        check("derive/item_key 随盐变化", k1.as_ref() != k2.as_ref());
    }

    // 3) AEAD roundtrip + 篡改
    {
        let key = random_key32();
        let blob = aead::seal(&key, b"vaultbox selftest payload", b"aad1").unwrap();
        let pt = aead::open(&key, &blob, b"aad1").unwrap();
        check("aead/roundtrip", pt.as_slice() == b"vaultbox selftest payload");
        check("aead/AAD 绑定", aead::open(&key, &blob, b"aad2").is_err());
        let mut bad = blob.clone();
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        check("aead/篡改 1 字节必失败", aead::open(&key, &bad, b"aad1").is_err());
    }

    // 4) 条目级加密 roundtrip + AAD 绑定
    {
        let dk = random_key32();
        let (salt, blob) =
            item::encrypt_item(&dk, "selftest-id", 0, "标题", "内容", Some("备注")).unwrap();
        let p = item::decrypt_item(&dk, "selftest-id", &salt, &blob).unwrap();
        check(
            "item/roundtrip",
            p.title == "标题" && p.content == "内容" && p.note.as_deref() == Some("备注"),
        );
        check(
            "item/AAD 绑定 id",
            item::decrypt_item(&dk, "wrong-id", &salt, &blob).is_err(),
        );
        let mut bad = blob.clone();
        bad[13] ^= 0x40;
        check("item/篡改必失败", item::decrypt_item(&dk, "selftest-id", &salt, &bad).is_err());
    }

    // 5) 内存库 export/import
    {
        let conn = memory::open_empty().unwrap();
        memory::meta_set(&conn, "k", "v").unwrap();
        let bytes = memory::export_bytes(&conn).unwrap();
        let conn2 = memory::import_bytes(&bytes).unwrap();
        check(
            "db/export->import 一致",
            memory::meta_get(&conn2, "k").unwrap().as_deref() == Some("v"),
        );
        check(
            "db/非法字节拒绝",
            matches!(memory::import_bytes(&[0xEE; 128]), Err(VaultError::Corrupt)),
        );
    }

    // 6) 密码策略
    check("policy/短密码拒绝", validate_password("abc").is_err());
    check("policy/纯数字拒绝", validate_password("123456789012").is_err());
    check("policy/弱口令拒绝", validate_password("1234567890").is_err());
    check("policy/合法通过", validate_password("Correct-Horse-9!").is_ok());

    // 7) 容器真实读写 + 篡改回归（走默认 64MiB 档，成本真实）
    {
        let dir = std::env::temp_dir().join(format!(
            "vaultbox_selftest_{}_{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("s.vault");
        let conn = memory::open_empty().unwrap();
        memory::meta_set(&conn, "selftest", "1").unwrap();
        let db = memory::export_bytes(&conn).unwrap();
        let pw = b"Selftest-Pass-9!";
        let q_ans = "my selftest answer phrase";
        container::create_vault(&vault, pw, &db, Some(("selftest 问题？", q_ans.as_bytes())))
            .map_err(|e| VaultError::Internal(format!("create_vault 失败: {e}")))?;
        let (_h, out, q) = container::open_vault(&vault, pw)
            .map_err(|e| VaultError::Internal(format!("open_vault 失败: {e}")))?;
        check(
            "container/创建->打开 字节一致 + 问题文本",
            out.as_slice() == db.as_slice() && q.as_deref() == Some("selftest 问题？"),
        );
        let pristine = std::fs::read(&vault).unwrap();
        check(
            "container/错误密码拒绝",
            matches!(container::open_vault(&vault, b"Wrong-Pass-999"), Err(VaultError::WrongPassword)),
        );
        // 篡改 wrapped_MK -> WrongPassword
        {
            let mut raw = pristine.clone();
            raw[0x50] ^= 0x01;
            std::fs::write(&vault, &raw).unwrap();
            check(
                "container/篡改 wrapped_MK -> WrongPassword",
                matches!(container::open_vault(&vault, pw), Err(VaultError::WrongPassword)),
            );
        }
        // 篡改 body -> Corrupt（先恢复原始文件，隔离上一用例的篡改）
        {
            std::fs::write(&vault, &pristine).unwrap();
            let mut raw = pristine.clone();
            let n = raw.len();
            raw[n - 2] ^= 0x01;
            std::fs::write(&vault, &raw).unwrap();
            check(
                "container/篡改 body -> Corrupt",
                matches!(container::open_vault(&vault, pw), Err(VaultError::Corrupt)),
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    if fail > 0 {
        return Err(VaultError::Internal(format!(
            "selftest 未通过：{pass} 通过 / {fail} 失败"
        )));
    }
    Ok(format!("selftest 全部通过：{pass} 项检查 ✓"))
}

// ---------------------------------------------------------------------------
// gen-vectors：生成黄金向量 JSON（仅维护者用）
// ---------------------------------------------------------------------------

fn cmd_gen_vectors(args: &[String]) -> Result<String, VaultError> {
    let usage = "crypto_cli gen-vectors <输出目录>";
    let dir = args
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| VaultError::BadRequest(format!("缺少输出目录。用法: {usage}")))?;
    std::fs::create_dir_all(&dir)?;

    // 1) kdf_argon2id.json：交叉验证黄金向量（固定参数/输入 -> 期望输出）
    let password: Vec<u8> = (1u8..=32).collect();
    let salt: Vec<u8> = (1u8..=16).collect();
    let p = KdfParams { m_cost: 32, t_cost: 3, p_cost: 4 };
    let out = kdf::derive_key(&password, &salt, &p)?;
    let expect = "4fa3bfb55e773b08dd080d6791d8999becbedae42633a1faab98ba6f7bd86b56";
    if hex::encode(out.as_ref()) != expect {
        return Err(VaultError::Internal("Argon2id 输出与黄金向量不一致，终止生成".to_string()));
    }
    let kdf_vec = serde_json::json!({
        "name": "argon2id-golden",
        "algorithm": "Argon2id v1.3",
        "params": { "m_cost_mib": 32, "m_cost_kib": 32768, "t_cost": 3, "p_cost": 4, "out_len": 32 },
        "password_hex": hex::encode(&password),
        "salt_hex": hex::encode(&salt),
        "expected_hex": expect,
        "note": "已用 argon2-cffi(libargon2 C 参考库, memory_cost=32768 KiB) 交叉验证一致"
    });
    std::fs::write(dir.join("kdf_argon2id.json"), serde_json::to_string_pretty(&kdf_vec)?)?;

    // 2) aead_aes256gcm.json：固定 nonce 向量（seal_with_nonce；仅向量/容器内部用）
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8;
    }
    let key32 = Key32::from(key);
    let nonce = [0x42u8; 12];
    let pt = b"vaultbox golden plaintext";
    let aad = b"golden-aad";
    let blob = aead::seal_with_nonce(&key32, &nonce, pt, aad)?;
    let aead_vec = serde_json::json!({
        "name": "aes-256-gcm-fixed-nonce",
        "algorithm": "AES-256-GCM",
        "key_hex": hex::encode(key.as_ref()),
        "nonce_hex": hex::encode(nonce),
        "plaintext_hex": hex::encode(pt),
        "aad_hex": hex::encode(aad),
        "expected_blob_hex": hex::encode(&blob),
        "blob_layout": "nonce(12)||ciphertext||tag(16)"
    });
    std::fs::write(dir.join("aead_aes256gcm.json"), serde_json::to_string_pretty(&aead_vec)?)?;

    Ok(format!(
        "黄金向量已生成到 {}:\n  - kdf_argon2id.json\n  - aead_aes256gcm.json",
        dir.display()
    ))
}
