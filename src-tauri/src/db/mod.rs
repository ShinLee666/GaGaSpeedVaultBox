//! db 模块：内存 SQLite（解锁后驻内存）+ 行级读写辅助。
//! 依赖方向：db 依赖 crypto？否——db 只依赖 error/util；加解密在 vault/item.rs。

pub mod memory;
pub mod rows;
