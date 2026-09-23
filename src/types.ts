/**
 * VaultBox 前端共享类型定义
 * 字段命名与 Rust DTO 保持一致（snake_case），与 CONTRACT §3 逐字对应
 */

/** 保险箱运行模式：本地单文件 / 联网同步 */
export type Mode = 'local' | 'remote' | null

/** 条目类型常量：0 账号 / 1 备注 / 2 密钥 */
export const KIND_ACCOUNT = 0
export const KIND_NOTE = 1
export const KIND_SECRET = 2

/** 条目类型 -> 中文名（搜索与左侧分类过滤使用） */
export const KIND_LABELS: Record<number, string> = {
  [KIND_ACCOUNT]: '账号',
  [KIND_NOTE]: '备注',
  [KIND_SECRET]: '密钥',
}

/** 表单下拉用条目类型选项 */
export const KIND_OPTIONS: { value: number; label: string }[] = [
  { value: KIND_ACCOUNT, label: '账号' },
  { value: KIND_NOTE, label: '备注' },
  { value: KIND_SECRET, label: '密钥' },
]

/** 由 kind 取中文名（未知类型兜底"条目"） */
export function kindLabel(kind: number): string {
  return KIND_LABELS[kind] ?? '条目'
}

/** 条目摘要（列表用，title 为解密后明文） */
export interface ItemSummaryDto {
  id: string
  kind: number
  title: string
  updated_at: number // epoch 毫秒（UTC）
}

/** 条目详情（解密后） */
export interface ItemDetailDto {
  id: string
  kind: number
  title: string
  content: string
  note?: string | null
  created_at: number
  updated_at: number
}

/** 同步结果计数 */
export interface SyncResult {
  pulled: number
  pushed: number
  conflicts: number
}

/** 远程测试连接结果 */
export interface RemoteTestResult {
  ok: boolean
  version?: string
  error?: string
}

/** 应用信息（关于页） */
export interface AppInfo {
  version: string
  /** 发行版形态：full 完整版（本地+联网） / store 微软商店版（纯本地存储） */
  edition: string
}

/** Rust 端错误载体（VaultErrorDto） */
export interface VaultErrorDto {
  code: string
  message: string
}

/** 服务器连接配置（不含任何凭据，只存内存/localStorage） */
export interface ServerCfg {
  address: string
  port: number
  https: boolean
}

/** 同步状态（store 内） */
export interface SyncState {
  /** idle 空闲 / syncing 同步中 / synced 同步完成 / error 出错 */
  state: 'idle' | 'syncing' | 'synced' | 'error'
  /** 冲突条目 id 列表（后端返回具体 id 前为空，弹窗按计数处理） */
  conflicts: string[]
}

/** 冲突三选：以本地为准 / 以服务器为准 / 复制为新条目 */
export type ConflictChoice = 'local' | 'server' | 'copy'
