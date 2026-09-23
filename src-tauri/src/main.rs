//! VaultBox 桌面入口（Tauri 2）。
//!
//! 真正的应用搭建逻辑在 lib.rs（`vaultbox_core::run()`），
//! 本文件只是让 Windows 打包时不弹出控制台窗口的最小壳。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    vaultbox_core::run()
}
