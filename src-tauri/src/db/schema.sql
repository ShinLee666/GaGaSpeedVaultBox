-- VaultBox 内存库 schema（设计 §5.1；CONTRACT §5）。
-- 表结构只描述"明文层"——实际落盘时整库被容器加密，且条目字段本身已密文化
-- （设计 §4.6），故明文结构只存在于解锁态内存。
-- 敏感判定：凡与用户秘密可关联的字段一律进加密载荷（title/content/note）；
-- 只把"不指向内容语义"的结构字段（uuid、时间戳、kind）留明文（排序/同步/分组用）。

PRAGMA journal_mode=OFF;   -- 纯内存 + 全量导出，不需要 WAL/回滚日志
PRAGMA foreign_keys=ON;

-- 元信息（明文，非敏感）：schema_version / created_at / last_saved_at /
-- kdf_hint / sync_last_pull / sync 版本标记 rev:<item-id> ...
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- 条目（密文载荷）：cipher_blob = nonce(12)||ciphertext||tag(16)（内部为加密 JSON）
CREATE TABLE IF NOT EXISTS items (
  id          TEXT PRIMARY KEY,    -- uuid v4，作为 AAD 绑定密文
  cipher_blob BLOB NOT NULL,       -- 加密 JSON 载荷
  item_salt   BLOB NOT NULL,       -- 条目级 HKDF 盐（16B）
  kind        INTEGER NOT NULL,    -- 0=账号类 1=备注类 2=密钥类（明文枚举）
  created_at  INTEGER NOT NULL,    -- epoch ms（明文）
  updated_at  INTEGER NOT NULL     -- epoch ms（明文，同步用）
);
CREATE INDEX IF NOT EXISTS idx_items_updated ON items(updated_at);

-- 设置（明文但低敏感：主题/锁定时间等，不含任何凭据）
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
