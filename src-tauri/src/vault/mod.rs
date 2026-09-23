//! vault 模块：容器读写（header/container）与条目级加解密（item）。
//! 依赖方向：vault 依赖 crypto；被 db/CLI/commands 依赖。

pub mod container;
pub mod header;
pub mod item;
