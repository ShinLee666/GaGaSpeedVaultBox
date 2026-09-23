//! 远程模式命令与 HTTP 客户端（CONTRACT §3/§7）。
//!
//! - remote_test / remote_register / remote_login / remote_logout
//! - 密码学协议（客户端侧自洽，服务器只存密文材料）：
//!   KEK = Argon2id(password, salt1, 密码档 64MiB/3/1)
//!   verifier = hex(AK)，AK = HKDF(KEK, salt=空, info="vaultbox.auth.v1")
//!   MK 随机 32B；wrapped_MK = AES-256-GCM(KEK, MK) 的 ct||tag（48B），
//!   nonce 由 SHA-256(域常量||AK||salt1||username) 确定性派生（服务器无 nonce 字段）。
//!   条目级加密与本地完全一致（cipher=seal(ITEM_KEY,…)，salt 随行存储），
//!   登录拉全量后逐行 decrypt 建内存库，DK=HKDF(MK)。
//!
//! 说明：问题/答案档（salt_q/wrapped_mk_q/security_q）注册时一并上报
//! （答案档 m=128MiB 客户端自算），但远程恢复流程不在本期契约内，
//! 服务器侧仅做存档。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;

use crate::commands::blocking;
use crate::commands::dto::{all_summaries, ItemSummaryDto, RemoteTestResult};
use crate::crypto::aead;
use crate::crypto::derive::{auth_key, data_key};
use crate::crypto::kdf::{self, KdfParams};
use crate::crypto::secret::{fill_random, key32_from_slice, random_key32, Key32};
use crate::db::memory;
use crate::error::VaultError;
use crate::state::{AppState, ServerCfg, Session, SessionMode};
use crate::util::{normalize_answer, now_ms, validate_answer, validate_password};
use crate::vault::container::QUESTION_TEXT_MAX_BYTES;

// ---------------------------------------------------------------------------
// HTTP 小客户端
// ---------------------------------------------------------------------------

/// 面向 vaultbox-server 的 HTTP 客户端（base = http(s)://address:port）。
pub(crate) struct Api {
    base: String,
    http: reqwest::Client,
}

impl Api {
    pub(crate) fn new(cfg: &ServerCfg) -> Result<Self, VaultError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| VaultError::Internal(format!("HTTP 客户端初始化失败: {e}")))?;
        Ok(Api {
            base: cfg.base_url(),
            http,
        })
    }
}

/// 请求；连接层失败归类 Unreachable / TlsError。
pub(crate) async fn api_request(
    api: &Api,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    json: Option<serde_json::Value>,
) -> Result<(u16, serde_json::Value), VaultError> {
    let mut rb = api.http.request(method, format!("{}{}", api.base, path));
    if let Some(t) = token {
        rb = rb.bearer_auth(t);
    }
    if let Some(v) = json {
        rb = rb.json(&v);
    }
    let resp = rb.send().await.map_err(map_http_err)?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| VaultError::Internal(format!("读取服务器响应失败: {e}")))?;
    let value: serde_json::Value = if text.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
    };
    Ok((status, value))
}

/// reqwest 错误 -> 契约错误码。
fn map_http_err(e: reqwest::Error) -> VaultError {
    if e.is_timeout() {
        return VaultError::Unreachable;
    }
    if e.is_connect() {
        // TLS/证书错误会以 connect 失败形态出现，检查错误链特征字符串
        let mut cause = std::error::Error::source(&e);
        while let Some(c) = cause {
            let s = c.to_string().to_lowercase();
            if s.contains("certificate")
                || s.contains("tls")
                || s.contains("schannel")
                || s.contains("handshake")
            {
                return VaultError::TlsError;
            }
            cause = c.source();
        }
        return VaultError::Unreachable;
    }
    VaultError::Unreachable
}

/// 服务器错误体 {code,message} -> VaultError。
pub(crate) fn map_server_error(status: u16, code: &str, message: &str) -> VaultError {
    match code {
        "conflict" => VaultError::Conflict(if message.is_empty() {
            "条目在别处被修改".to_string()
        } else {
            message.to_string()
        }),
        "unauthorized" => VaultError::Unauthorized,
        "not_found" => VaultError::NotFound,
        "wrong_password" => VaultError::WrongPassword,
        "answer_wrong" => VaultError::AnswerWrong,
        "tls_error" => VaultError::TlsError,
        "unreachable" => VaultError::Unreachable,
        "bad_request" => VaultError::BadRequest(if message.is_empty() {
            "服务器拒绝了请求".to_string()
        } else {
            message.to_string()
        }),
        _ => {
            if status >= 500 {
                VaultError::Internal(format!("服务器错误({status}): {message}"))
            } else {
                VaultError::BadRequest(if message.is_empty() {
                    format!("服务器返回异常({status})")
                } else {
                    message.to_string()
                })
            }
        }
    }
}

/// 期望 2xx；否则从错误体 {code,message} 归类抛出。
pub(crate) async fn expect_ok(
    api: &Api,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    json: Option<serde_json::Value>,
) -> Result<serde_json::Value, VaultError> {
    let (status, body) = api_request(api, method, path, token, json).await?;
    if (200..300).contains(&status) {
        return Ok(body);
    }
    let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
    let message = body
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Err(map_server_error(status, code, message))
}

/// URL 查询参数编码（username 等；仅安全字符 + 百分号编码其余）。
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 服务器契约类型（CONTRACT §7）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct KdfJson {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

/// 注册请求体（仅序列化上行；字段由服务器端消费，本端不读）。
#[derive(Debug, Serialize)]
struct RegisterBody {
    username: String,
    verifier: String,
    salt1: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    salt_q: Option<String>,
    kdf: KdfJson,
    wrapped_mk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_mk_q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    security_q: Option<String>,
}

/// GET /auth/meta 响应。
/// salt_q/wrapped_mk_q/security_q 为远程答案恢复存档（本期无远程恢复 UI），
/// 登录只消费 salt1/kdf/wrapped_mk；字段保留以备未来实现。
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(crate) struct AuthMeta {
    pub salt1: String,
    #[serde(default)]
    pub salt_q: Option<String>,
    pub kdf: KdfJson,
    pub wrapped_mk: String,
    #[serde(default)]
    pub wrapped_mk_q: Option<String>,
    #[serde(default)]
    pub security_q: Option<String>,
}

/// GET /items 里的单条。
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ServerItem {
    pub id: String,
    pub kind: u8,
    pub cipher: String,
    pub salt: String,
    pub rev: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Deserialize)]
struct ItemsResp {
    items: Vec<ServerItem>,
}

/// PUT /items/:id 请求体。
#[derive(Debug, Serialize)]
struct PutBody {
    kind: u8,
    cipher: String,
    salt: String,
    rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_rev: Option<String>,
    updated_at: u64,
}

// ---------------------------------------------------------------------------
// 远程密钥材料协议（确定性 nonce，客户端自洽）
// ---------------------------------------------------------------------------

const DOMAIN_NONCE_PW: &[u8] = b"vaultbox.remote.wrap.v1";
const DOMAIN_NONCE_Q: &[u8] = b"vaultbox.remote.wrapq.v1";
/// wrapped_MK / wrapped_MK_Q 的 GCM AAD（跨注册/登录不变的域常量）。
const AAD_REMOTE_MK: &[u8] = b"vaultbox.remote.mk.v1";

/// 确定性 nonce：SHA-256(域常量 || AK || salt1 || username) 前 12 字节。
fn remote_nonce(ak: &Key32, salt1: &[u8; 16], username: &str, domain: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(ak.as_ref());
    h.update(salt1);
    h.update(username.as_bytes());
    let d = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&d[..12]);
    n
}

fn check_username(username: &str) -> Result<(), VaultError> {
    let len = username.chars().count();
    if !(3..=64).contains(&len) {
        return Err(VaultError::BadRequest(
            "用户名长度须为 3~64 个字符".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// remote_test
// ---------------------------------------------------------------------------

/// 远程连接测试（CONTRACT §3：{address,port,https} -> {ok,version?,error?}）。
/// 失败不抛错，统一放 {ok:false,error} 返回。
#[tauri::command(rename_all = "snake_case")]
pub async fn remote_test(
    address: String,
    port: u16,
    https: bool,
) -> Result<RemoteTestResult, VaultError> {
    let cfg = ServerCfg {
        address,
        port,
        https,
    };
    let api = match Api::new(&cfg) {
        Ok(a) => a,
        Err(e) => {
            return Ok(RemoteTestResult {
                ok: false,
                version: None,
                error: Some(e.to_string()),
            })
        }
    };
    match api_request(&api, reqwest::Method::GET, "/health", None, None).await {
        Ok((status, body)) => {
            if (200..300).contains(&status) {
                let version = body
                    .get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Ok(RemoteTestResult {
                    ok: true,
                    version,
                    error: None,
                })
            } else {
                Ok(RemoteTestResult {
                    ok: false,
                    version: None,
                    error: Some(format!("服务器返回异常状态码 {status}")),
                })
            }
        }
        Err(e) => {
            let msg = match &e {
                VaultError::TlsError => "证书无效",
                VaultError::Unauthorized => "登录已过期，请重新登录",
                _ => "无法连接服务器，请检查地址与网络",
            };
            Ok(RemoteTestResult {
                ok: false,
                version: None,
                error: Some(msg.to_string()),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// remote_register
// ---------------------------------------------------------------------------

/// 远程注册（CONTRACT §3）。成功后不自动登录，前端转登录页。
#[tauri::command(rename_all = "snake_case")]
pub async fn remote_register(
    address: String,
    port: u16,
    https: bool,
    username: String,
    password: String,
    question: Option<String>,
    answer: Option<String>,
) -> Result<(), VaultError> {
    check_username(&username)?;
    validate_password(&password)?;
    if question.is_some() != answer.is_some() {
        return Err(VaultError::BadRequest(
            "保护问题与答案必须同有同无".to_string(),
        ));
    }
    let answer_norm = answer.as_deref().map(normalize_answer);
    if let Some(ans) = &answer_norm {
        validate_answer(ans, &password)?;
        if let Some(q) = &question {
            if q.trim().is_empty() {
                return Err(VaultError::BadRequest("保护问题不能为空".to_string()));
            }
            if q.len() > QUESTION_TEXT_MAX_BYTES {
                return Err(VaultError::BadRequest(format!(
                    "保护问题过长（最多 {QUESTION_TEXT_MAX_BYTES} 字节）"
                )));
            }
        }
    }

    let user2 = username.clone();
    let pw2 = password.clone();
    let q_pair: Option<(String, String)> =
        match (question.clone(), answer_norm) {
            (Some(q), Some(a)) => Some((q, a)),
            _ => None,
        };
    // Argon2id x2（密码档+答案档）放阻塞线程
    let body: RegisterBody = blocking(move || -> Result<RegisterBody, VaultError> {
        let mut salt1 = [0u8; 16];
        fill_random(&mut salt1);
        let kek = kdf::derive_key(pw2.as_bytes(), &salt1, &KdfParams::password_default())?;
        let ak = auth_key(&kek);
        let verifier = hex::encode(ak.as_ref());
        let mk = random_key32();

        let nonce = remote_nonce(&ak, &salt1, &user2, DOMAIN_NONCE_PW);
        let blob = aead::seal_with_nonce(&kek, &nonce, mk.as_ref(), AAD_REMOTE_MK)?;
        let wrapped_mk = hex::encode(&blob[12..]); // 仅 ct||tag 48B

        let mut salt_q: Option<[u8; 16]> = None;
        let mut wrapped_mk_q: Option<String> = None;
        if let Some((_q_text, ans)) = &q_pair {
            let mut sq = [0u8; 16];
            fill_random(&mut sq);
            let kek_q = kdf::derive_key(ans.as_bytes(), &sq, &KdfParams::answer_default())?;
            let ak_q = auth_key(&kek_q);
            let nonce_q = remote_nonce(&ak_q, &sq, &user2, DOMAIN_NONCE_Q);
            let blob_q = aead::seal_with_nonce(&kek_q, &nonce_q, mk.as_ref(), AAD_REMOTE_MK)?;
            salt_q = Some(sq);
            wrapped_mk_q = Some(hex::encode(&blob_q[12..]));
        }

        Ok(RegisterBody {
            username: user2.clone(),
            verifier,
            salt1: hex::encode(&salt1),
            salt_q: salt_q.map(|s| hex::encode(s)),
            kdf: KdfJson {
                m: KdfParams::password_default().m_cost,
                t: KdfParams::password_default().t_cost,
                p: KdfParams::password_default().p_cost,
            },
            wrapped_mk,
            wrapped_mk_q,
            security_q: q_pair.as_ref().map(|(q, _)| q.clone()),
        })
    })
    .await?;

    let cfg = ServerCfg {
        address,
        port,
        https,
    };
    let api = Api::new(&cfg)?;
    // 三个可选字段仅上行存档（服务器消费）；此处消费一次避免 dead_code 提示
    let _ = (
        body.salt_q.is_some(),
        body.wrapped_mk_q.is_some(),
        body.security_q.is_some(),
    );
    let json = serde_json::to_value(&body)
        .map_err(|e| VaultError::Internal(format!("注册数据序列化失败: {e}")))?;
    let _ = expect_ok(
        &api,
        reqwest::Method::POST,
        "/auth/register",
        None,
        Some(json),
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// remote_login
// ---------------------------------------------------------------------------

/// 远程登录 + 全量拉取（CONTRACT §3 -> ItemSummaryDto[]）。
#[tauri::command(rename_all = "snake_case")]
pub async fn remote_login(
    address: String,
    port: u16,
    https: bool,
    username: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<Vec<ItemSummaryDto>, VaultError> {
    check_username(&username)?;
    {
        let mut guard = state.lock();
        *guard = None;
    }

    let cfg = ServerCfg {
        address,
        port,
        https,
    };
    let api = Api::new(&cfg)?;

    // 1) 拉账户元数据（salt1 / kdf / wrapped_mk）
    let meta_path = format!("/auth/meta?username={}", urlencode(&username));
    let meta_body = expect_ok(&api, reqwest::Method::GET, &meta_path, None, None).await?;
    let meta: AuthMeta = serde_json::from_value(meta_body)
        .map_err(|e| VaultError::Internal(format!("服务器元数据无法解析: {e}")))?;
    let salt1: [u8; 16] = {
        let b = hex::decode(&meta.salt1).map_err(|_| VaultError::Corrupt)?;
        b.try_into().map_err(|_| VaultError::Corrupt)?
    };
    let kdf_json = meta.kdf.clone();
    let kdf = kdf_params_from_json(&kdf_json)?;
    let wrapped_hex = meta.wrapped_mk.clone();

    // 2) 派生 KEK -> verifier + 解开 MK（Argon2id 放阻塞线程）
    let user2 = username.clone();
    let pw2 = password.clone();
    let (mk, dk, verifier) = blocking(move || -> Result<(Key32, Key32, String), VaultError> {
        let kek = kdf::derive_key(pw2.as_bytes(), &salt1, &kdf)?;
        let ak = auth_key(&kek);
        let verifier = hex::encode(ak.as_ref());
        let nonce = remote_nonce(&ak, &salt1, &user2, DOMAIN_NONCE_PW);
        let ct = hex::decode(&wrapped_hex).map_err(|_| VaultError::Corrupt)?;
        if ct.len() != 48 {
            return Err(VaultError::Corrupt);
        }
        let pt = aead::open_with_nonce(&kek, &nonce, &ct, AAD_REMOTE_MK)
            .map_err(|_| VaultError::WrongPassword)?;
        let mk = key32_from_slice(&pt).ok_or(VaultError::Corrupt)?;
        let dk = data_key(&mk);
        Ok((mk, dk, verifier))
    })
    .await?;

    // 3) 登录换取 JWT（verifier 不符 -> 服务器 401 = 密码错误）
    let login_body = serde_json::json!({ "username": username, "verifier": verifier });
    let (status, body) = api_request(
        &api,
        reqwest::Method::POST,
        "/auth/login",
        None,
        Some(login_body),
    )
    .await?;
    if status == 401 {
        return Err(VaultError::WrongPassword);
    }
    if !(200..300).contains(&status) {
        let code = body.get("code").and_then(|v| v.as_str()).unwrap_or("");
        let msg = body.get("message").and_then(|v| v.as_str()).unwrap_or("");
        return Err(map_server_error(status, code, msg));
    }
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VaultError::Internal("服务器登录响应缺少 token".to_string()))?
        .to_string();

    // 4) 全量拉取条目 -> 建内存库（条目密文与本地同构，可直接落行）
    let items = fetch_items_since(&api, &token, 0).await?;
    let conn = memory::open_empty()?;
    let now = now_ms();
    for it in &items {
        let salt = hex::decode(&it.salt).map_err(|_| VaultError::Corrupt)?;
        let blob = hex::decode(&it.cipher).map_err(|_| VaultError::Corrupt)?;
        crate::db::rows::insert(
            &conn,
            &it.id,
            it.kind,
            &salt,
            &blob,
            it.created_at,
            it.updated_at,
        )?;
        memory::meta_set(&conn, &format!("sync_rev:{}", it.id), &it.rev)?;
    }
    memory::meta_set(&conn, "sync_last_pull", &now.to_string())?;

    let summaries = all_summaries(&dk, &conn)?;
    {
        let mut guard = state.lock();
        *guard = Some(Session {
            mode: SessionMode::Remote,
            vault_path: None,
            server_cfg: Some(cfg),
            token: Some(token),
            mk,
            dk,
            db: conn,
            dirty: false,
            pending_conflicts: Vec::new(),
            last_activity_ms: now,
        });
    }
    Ok(summaries)
}

/// 远程登出（CONTRACT §3：remote_logout -> null；清空会话）。
#[tauri::command]
pub fn remote_logout(state: State<'_, AppState>) -> Result<(), VaultError> {
    let mut guard = state.lock();
    *guard = None;
    Ok(())
}

// ---------------------------------------------------------------------------
// sync.rs 共用（pub(crate)）
// ---------------------------------------------------------------------------

/// KdfJson -> KdfParams（校验取值区间，非法判 Corrupt）。
pub(crate) fn kdf_params_from_json(j: &KdfJson) -> Result<KdfParams, VaultError> {
    if j.m < 8 || j.m > 255 || j.t < 1 || j.t > 10 || j.p < 1 || j.p > 4 {
        return Err(VaultError::Corrupt);
    }
    Ok(KdfParams {
        m_cost: j.m,
        t_cost: j.t,
        p_cost: j.p,
    })
}

/// GET /items?since=<ms>（JWT）。
pub(crate) async fn fetch_items_since(
    api: &Api,
    token: &str,
    since: u64,
) -> Result<Vec<ServerItem>, VaultError> {
    let body = expect_ok(
        api,
        reqwest::Method::GET,
        &format!("/items?since={since}"),
        Some(token),
        None,
    )
    .await?;
    let resp: ItemsResp = serde_json::from_value(body)
        .map_err(|e| VaultError::Internal(format!("服务器条目列表无法解析: {e}")))?;
    Ok(resp.items)
}

/// PUT /items/:id（JWT）。成功 Ok；409 -> Err(Conflict)。
pub(crate) async fn put_item(
    api: &Api,
    token: &str,
    id: &str,
    kind: u8,
    salt_hex: &str,
    blob_hex: &str,
    rev: &str,
    base_rev: Option<&str>,
    updated_at: u64,
) -> Result<(), VaultError> {
    let body = PutBody {
        kind,
        cipher: blob_hex.to_string(),
        salt: salt_hex.to_string(),
        rev: rev.to_string(),
        base_rev: base_rev.map(|s| s.to_string()),
        updated_at,
    };
    let json = serde_json::to_value(&body)
        .map_err(|e| VaultError::Internal(format!("条目序列化失败: {e}")))?;
    let _ = expect_ok(
        api,
        reqwest::Method::PUT,
        &format!("/items/{}", urlencode(id)),
        Some(token),
        Some(json),
    )
    .await?;
    Ok(())
}

/// DELETE /items/:id（JWT）。404 视为已删除（幂等）。
pub(crate) async fn delete_item(api: &Api, token: &str, id: &str) -> Result<(), VaultError> {
    match expect_ok(
        api,
        reqwest::Method::DELETE,
        &format!("/items/{}", urlencode(id)),
        Some(token),
        None,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(VaultError::NotFound) => Ok(()),
        Err(e) => Err(e),
    }
}
