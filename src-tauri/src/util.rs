//! 通用小工具：时间戳、密码强度策略、答案规范化。
//!
//! 密码强度规则（CONTRACT §1，前后端一致）：长度 >= 10，非纯数字，
//! 非内置弱口令清单。答案规范化（NFKC + trim + 全小写）按 CONTRACT 约定
//! 由调用方/CLI 在入口处执行（本内核不处理 Unicode 规范化的历史包袱，
//! 但统一收口在本模块便于 CLI 与 commands 复用）。

use crate::error::VaultError;
use std::time::{SystemTime, UNIX_EPOCH};
use unicode_normalization::UnicodeNormalization;

/// 当前 UTC 时间戳，单位毫秒（u64，CONTRACT §1）。
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 内置弱口令清单（CONTRACT §1 要求的小清单，可后续扩充到 top100）。
pub const WEAK_PASSWORDS: &[&str] = &[
    "1234567890",
    "123456789",
    "password",
    "1111111111",
    "0000000000",
    "iloveyou",
    "qwertyuiop",
    "letmein",
    "dragon",
    "monkey",
    "password1",
    "abc1234567",
];

/// 校验密码强度。规则（CONTRACT §1）：
/// 1) 长度 >= 10（按字符计，不按字节）；
/// 2) 不能是纯数字；
/// 3) 不能命中内置弱口令清单（比较前 trim + 全小写）。
pub fn validate_password(pw: &str) -> Result<(), VaultError> {
    let chars: Vec<char> = pw.chars().collect();
    if chars.len() < 10 {
        return Err(VaultError::WeakPassword(
            "密码长度至少 10 位".to_string(),
        ));
    }
    // 纯数字判定：全部字符都是 ASCII 数字
    if !chars.is_empty() && chars.iter().all(|c| c.is_ascii_digit()) {
        return Err(VaultError::WeakPassword(
            "密码不能是纯数字".to_string(),
        ));
    }
    let key = pw.trim().to_lowercase();
    if WEAK_PASSWORDS.contains(&key.as_str()) {
        return Err(VaultError::WeakPassword(
            "密码过于常见，请更换".to_string(),
        ));
    }
    Ok(())
}

/// 校验保护问题答案：>= 8 字符且不得与密码相同（设计 §4.4）。
pub fn validate_answer(answer: &str, password: &str) -> Result<(), VaultError> {
    let normalized = normalize_answer(answer);
    if normalized.chars().count() < 8 {
        return Err(VaultError::BadRequest(
            "保护问题答案至少 8 个字符".to_string(),
        ));
    }
    if normalized == normalize_answer(password) {
        return Err(VaultError::BadRequest(
            "保护问题答案不能与密码相同".to_string(),
        ));
    }
    Ok(())
}

/// 答案规范化：Unicode NFKC + trim + 全小写（CONTRACT §1；设计 §4.4）。
/// 中文不受大小写影响；全角字符经 NFKC 折叠为半角，保证跨输入法一致。
pub fn normalize_answer(raw: &str) -> String {
    raw.nfkc().collect::<String>().trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_rules() {
        // 太短
        assert!(validate_password("short1").is_err());
        // 长度够但纯数字
        assert!(validate_password("123456789012").is_err());
        // 命中弱口令清单
        assert!(validate_password("1234567890").is_err());
        assert!(validate_password("PASSWORD").is_err());
        assert!(validate_password(" Password ").is_err());
        // 合法密码
        assert!(validate_password("Correct-Horse-9!").is_ok());
        assert!(validate_password("强密码测试用例@2026九").is_ok());
        // 10 位整好
        assert!(validate_password("a1b2c3d4e5").is_ok());
    }

    #[test]
    fn answer_rules() {
        assert!(validate_answer("short", "Correct-Horse-9!").is_err());
        assert!(validate_answer("my answer phrase", "Correct-Horse-9!").is_ok());
        // 答案 == 密码被拒
        assert!(validate_answer("Same-As-Pass-123", "Same-As-Pass-123").is_err());
    }

    #[test]
    fn normalize_answer_forms() {
        // NFKC：全角字母折叠为半角；大小写与首尾空白归一
        assert_eq!(normalize_answer(" Ａｎｓｗｅｒ 42 "), "answer 42");
        assert_eq!(normalize_answer("My Pet Name"), "my pet name");
        // 中文不受影响
        assert_eq!(normalize_answer("我的宠物叫旺财"), "我的宠物叫旺财");
    }

    #[test]
    fn now_ms_monotonic() {
        let a = now_ms();
        let b = now_ms();
        assert!(b >= a);
        // 与系统秒级时间同量级
        let sec = a / 1000;
        assert!(sec > 1_600_000_000, "时间戳明显异常: {sec}");
    }
}
