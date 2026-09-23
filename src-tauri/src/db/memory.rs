//! 内存 SQLite：建库 / 全量导出 / 全量导入（CONTRACT §5 db/memory.rs；T1.6）。
//!
//! 导出：`sqlite3_serialize`（rusqlite 0.32 的 `Connection::serialize`，零落盘、
//! 一致性快照）。导入：rusqlite 0.32 把 `deserialize` 收窄为只接受 sqlite 自有
//! 内存（OwnedData，无公开的 from_vec 构造），故这里用 `sqlite3_malloc64` 拷贝
//! 后经 `sqlite3_deserialize` 装载——全程不落盘（优于 CONTRACT 备注中的
//! backup+临时文件备选）。调用前先校验 SQLite 文件魔数，避免把任意字节交给
//! deserialize。

use rusqlite::{Connection, DatabaseName};
use zeroize::Zeroizing;

use crate::error::VaultError;
#[cfg(test)]
use crate::util::now_ms;

/// SQLite 文件头魔数（前 16 字节）。
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// 建一个空的、执行过 schema 的内存库。
pub fn open_empty() -> Result<Connection, VaultError> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(include_str!("schema.sql"))?;
    Ok(conn)
}

/// 内存库 -> 明文库字节（"保存"的数据源；返回敏感字节，用后即零化）。
pub fn export_bytes(conn: &Connection) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    // serialize 可能返回零拷贝共享视图（Shared），必须立即复制为自有字节
    let data = conn.serialize(DatabaseName::Main)?;
    let bytes = data.to_vec();
    Ok(Zeroizing::new(bytes))
}

/// 明文库字节 -> 内存库（解锁加载）。字节用完由调用方清零。
/// 非 SQLite 内容 / 长度过短返回 Corrupt。
pub fn import_bytes(bytes: &[u8]) -> Result<Connection, VaultError> {
    if bytes.len() < 128 || &bytes[..16] != SQLITE_MAGIC {
        return Err(VaultError::Corrupt);
    }
    let conn = Connection::open_in_memory()?;
    unsafe {
        let handle = conn.handle();
        // deserialize 接管后由 sqlite 负责释放：缓冲区必须来自 sqlite3_malloc64
        let buf = rusqlite::ffi::sqlite3_malloc64(bytes.len() as u64);
        if buf.is_null() {
            return Err(VaultError::Internal("内存不足".to_string()));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), bytes.len());
        let rc = rusqlite::ffi::sqlite3_deserialize(
            handle,
            c"main".as_ptr(),
            buf.cast::<u8>(),
            bytes.len() as i64,
            bytes.len() as i64,
            (rusqlite::ffi::SQLITE_DESERIALIZE_FREEONCLOSE
                | rusqlite::ffi::SQLITE_DESERIALIZE_RESIZEABLE) as u32,
        );
        if rc != rusqlite::ffi::SQLITE_OK {
            // 失败路径不手动释放：若 sqlite 已接管会在 close 时释放（安全），
            // 未接管则仅泄漏一小块缓冲（安全）；避免双重释放。
            return Err(VaultError::Corrupt);
        }
    }
    // 导入后执行幂等 schema（索引/PRAGMA 兜底）
    conn.execute_batch(include_str!("schema.sql"))?;
    Ok(conn)
}

/// 写 meta 键值（幂等）。
pub fn meta_set(conn: &Connection, key: &str, value: &str) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![key, value],
    )?;
    Ok(())
}

/// 读 meta 键值（不存在返回 None）。
pub fn meta_get(conn: &Connection, key: &str) -> Result<Option<String>, VaultError> {
    let mut stmt = conn.prepare("SELECT value FROM meta WHERE key=?1")?;
    let mut rows = stmt.query(rusqlite::params![key])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// 删除 meta 键（如条目删除时清理其 rev 标记）。
pub fn meta_del(conn: &Connection, key: &str) -> Result<(), VaultError> {
    conn.execute("DELETE FROM meta WHERE key=?1", rusqlite::params![key])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_tables_exist() {
        let conn = open_empty().unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name IN ('meta','items','settings')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn export_import_roundtrip() {
        let conn = open_empty().unwrap();
        conn.execute_batch(
            "INSERT INTO meta(key,value) VALUES('a','1');
             INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
             VALUES('i1',x'001122',x'ff',1,10,20);
             INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
             VALUES('i2',x'3344',x'ee',2,30,40);
             INSERT INTO settings(key,value) VALUES('theme','dark');",
        )
        .unwrap();
        let bytes = export_bytes(&conn).unwrap();
        assert!(bytes.len() > 100);

        let conn2 = import_bytes(&bytes).unwrap();
        let n: i64 = conn2
            .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        let v: String = conn2
            .query_row("SELECT value FROM settings WHERE key='theme'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(v, "dark");
    }

    #[test]
    fn import_garbage_rejected() {
        let garbage = [0xDEu8; 512];
        let err = import_bytes(&garbage).unwrap_err();
        assert!(matches!(err, VaultError::Corrupt), "{err:?}");
    }

    #[test]
    fn meta_set_get_del() {
        let conn = open_empty().unwrap();
        meta_set(&conn, "k", "v1").unwrap();
        assert_eq!(meta_get(&conn, "k").unwrap().as_deref(), Some("v1"));
        meta_set(&conn, "k", "v2").unwrap();
        assert_eq!(meta_get(&conn, "k").unwrap().as_deref(), Some("v2"));
        meta_del(&conn, "k").unwrap();
        assert_eq!(meta_get(&conn, "k").unwrap(), None);
        // 空库时间戳写入（防止误删引用）
        meta_set(&conn, "now", &now_ms().to_string()).unwrap();
    }
}
