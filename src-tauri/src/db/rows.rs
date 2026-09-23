//! items 表的行级读写辅助（纯 SQL，不含密码学；加解密在 vault/item.rs）。
//! CLI 与 tauri commands 共用本模块，保证两条调用链行为一致。

use rusqlite::{params, Connection};

/// 内存中的一行条目（cipher_blob 等为密文材料，返回后由调用方处理）。
#[derive(Debug, Clone)]
pub struct ItemRow {
    pub id: String,
    pub kind: u8,
    pub salt: Vec<u8>,
    pub blob: Vec<u8>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// 插入新条目。
pub fn insert(
    conn: &Connection,
    id: &str,
    kind: u8,
    salt: &[u8],
    blob: &[u8],
    created_at: u64,
    updated_at: u64,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![id, blob, salt, kind as i64, created_at as i64, updated_at as i64],
    )?;
    Ok(())
}

/// 覆盖更新某条目（重加密后写回；created_at 不动）。
pub fn update_cipher(
    conn: &Connection,
    id: &str,
    kind: u8,
    salt: &[u8],
    blob: &[u8],
    updated_at: u64,
) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE items SET cipher_blob=?1, item_salt=?2, kind=?3, updated_at=?4
         WHERE id=?5",
        params![blob, salt, kind as i64, updated_at as i64, id],
    )
}

/// 覆盖整行（联网同步"以服务器为准"时使用：含 created_at 与旧盐替换）。
pub fn replace_row(conn: &Connection, row: &ItemRow) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO items(id,cipher_blob,item_salt,kind,created_at,updated_at)
         VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(id) DO UPDATE SET
           cipher_blob=excluded.cipher_blob, item_salt=excluded.item_salt,
           kind=excluded.kind, created_at=excluded.created_at,
           updated_at=excluded.updated_at",
        params![
            row.id,
            row.blob,
            row.salt,
            row.kind as i64,
            row.created_at as i64,
            row.updated_at as i64
        ],
    )?;
    Ok(())
}

/// 删除条目。返回受影响行数（0 = 不存在）。
pub fn delete(conn: &Connection, id: &str) -> rusqlite::Result<usize> {
    conn.execute("DELETE FROM items WHERE id=?1", params![id])
}

/// 按 id 取单行。
pub fn load_one(conn: &Connection, id: &str) -> rusqlite::Result<Option<ItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,cipher_blob,item_salt,kind,created_at,updated_at
         FROM items WHERE id=?1",
    )?;
    let mut rows = stmt.query(params![id])?;
    let row = rows.next()?;
    match row {
        Some(r) => Ok(Some(row_from(r)?)),
        None => Ok(None),
    }
}

/// 全量取行（按 updated_at 升序）。
pub fn load_all(conn: &Connection) -> rusqlite::Result<Vec<ItemRow>> {
    let mut stmt = conn.prepare(
        "SELECT id,cipher_blob,item_salt,kind,created_at,updated_at
         FROM items ORDER BY updated_at ASC",
    )?;
    let rows = stmt.query_map([], |r| row_from(r))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

/// 条目数。
pub fn count(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
}

fn row_from(r: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    Ok(ItemRow {
        id: r.get(0)?,
        blob: r.get(1)?,
        salt: r.get(2)?,
        kind: r.get::<_, i64>(3)? as u8,
        created_at: r.get::<_, i64>(4)? as u64,
        updated_at: r.get::<_, i64>(5)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::memory;

    #[test]
    fn crud_roundtrip() {
        let conn = memory::open_empty().unwrap();
        insert(&conn, "id1", 0, &[1u8; 16], &[2u8; 40], 100, 100).unwrap();
        insert(&conn, "id2", 1, &[3u8; 16], &[4u8; 40], 200, 200).unwrap();
        assert_eq!(count(&conn).unwrap(), 2);

        assert_eq!(load_one(&conn, "id1").unwrap().unwrap().id, "id1");
        assert!(load_one(&conn, "nope").unwrap().is_none());

        update_cipher(&conn, "id1", 2, &[5u8; 16], &[6u8; 40], 300).unwrap();
        let row = load_one(&conn, "id1").unwrap().unwrap();
        assert_eq!(row.kind, 2);
        assert_eq!(row.updated_at, 300);
        assert_eq!(row.created_at, 100, "created_at 不应被 update 改变");

        let rows = load_all(&conn).unwrap();
        assert_eq!(rows.len(), 2);

        assert_eq!(delete(&conn, "id1").unwrap(), 1);
        assert_eq!(delete(&conn, "id1").unwrap(), 0, "重复删除应为 0 行");
        assert_eq!(count(&conn).unwrap(), 1);
    }

    #[test]
    fn replace_row_upsert() {
        let conn = memory::open_empty().unwrap();
        let row = ItemRow {
            id: "r1".into(),
            kind: 1,
            salt: vec![7u8; 16],
            blob: vec![8u8; 44],
            created_at: 1,
            updated_at: 2,
        };
        replace_row(&conn, &row).unwrap();
        let row2 = ItemRow {
            id: "r1".into(),
            kind: 0,
            salt: vec![9u8; 16],
            blob: vec![10u8; 44],
            created_at: 11,
            updated_at: 22,
        };
        replace_row(&conn, &row2).unwrap();
        let got = load_one(&conn, "r1").unwrap().unwrap();
        assert_eq!(got.kind, 0);
        assert_eq!(got.created_at, 11);
        assert_eq!(got.updated_at, 22);
    }
}
