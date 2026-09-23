//! VaultBox 桌面端 crate 根（Tauri 2 薄层）。
//!
//! 模块布局（与 rust-core 同源复制）：`crypto <- vault <- db` 全部保留；
//! 新增 `commands/`（#[tauri::command] 薄层，接口逐字对齐 CONTRACT §3）。
//! 核心模块（crypto/vault/db/util/state/error）**不依赖 tauri**，
//! bin/crypto_cli.rs 与 commands 共用同一套模块。
//!
//! 依赖方向（禁止反向）：`crypto <- vault <- db / commands / CLI`；
//! commands 依赖 crypto/vault/db/util/state/error。
//!
//! Tauri 侧职责只在这里（lib.rs）：
//! - 注册剪贴板插件（复制秘密内容用）；
//! - manage 全局 AppState（Mutex<Option<Session>>，None=锁定）；
//! - invoke_handler 注册 CONTRACT §3 全部 20 个命令；
//! - on_window_event：CloseRequested 且 Session.dirty 时先同步 flush 再放行。

pub mod commands;
pub mod crypto;
pub mod db;
pub mod error;
pub mod state;
pub mod util;
pub mod vault;

use std::sync::Mutex;

use state::AppState;

pub const APP_VERSION: &str = "0.1.0";

/// 应用搭建（main.rs 调用；集成测试亦可复用）。
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState(Mutex::new(None)));

    // 完整版（默认 feature=remote）：注册全部 20 个命令（含联网注册/登录/同步）。
    #[cfg(feature = "remote")]
    let builder = builder.invoke_handler(tauri::generate_handler![
        commands::ping,
        commands::app_info,
        commands::local::init_local,
        commands::local::unlock_local,
        commands::local::lock,
        commands::save::flush_now,
        commands::items::item_create,
        commands::items::item_update,
        commands::items::item_delete,
        commands::items::item_get,
        commands::items::item_list,
        commands::save::change_password,
        commands::recover::recover_reset,
        commands::remote::remote_test,
        commands::remote::remote_register,
        commands::remote::remote_login,
        commands::remote::remote_logout,
        commands::sync::sync_now,
        commands::sync::sync_conflict_resolve,
    ]);

    // 微软商店版（--no-default-features）：纯本地存储，不编译任何联网代码。
    #[cfg(not(feature = "remote"))]
    let builder = builder.invoke_handler(tauri::generate_handler![
        commands::ping,
        commands::app_info,
        commands::local::init_local,
        commands::local::unlock_local,
        commands::local::lock,
        commands::save::flush_now,
        commands::items::item_create,
        commands::items::item_update,
        commands::items::item_delete,
        commands::items::item_get,
        commands::items::item_list,
        commands::save::change_password,
        commands::recover::recover_reset,
    ]);

    builder
        .on_window_event(|window, event| {
            // 关闭窗口时：本地模式若存在未保存变更，先尝试同步落盘再放行
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                use tauri::Manager;
                let state = window.state::<AppState>();
                let mut guard = state.lock();
                if let Some(sess) = guard.as_mut() {
                    if sess.mode == state::SessionMode::Local && sess.dirty {
                        if let Err(e) = commands::save::flush_session(sess) {
                            // 落盘失败不应把用户困在无法关闭的窗口里：记录后放行
                            eprintln!("[VaultBox] 关闭前 flush 失败: {e}");
                        }
                    }
                    sess.dirty = false;
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running VaultBox");
}

/// 供命令层判断会话是否已解锁的小助手：返回会话可变引用。
/// 注意：guard 不得跨 await 持有（调用方遵守）。
pub fn session_mut<'a>(
    state: &'a AppState,
) -> Result<std::sync::MutexGuard<'a, Option<state::Session>>, error::VaultError> {
    let guard = state.lock();
    if guard.is_none() {
        return Err(error::VaultError::NotUnlocked);
    }
    Ok(guard)
}
