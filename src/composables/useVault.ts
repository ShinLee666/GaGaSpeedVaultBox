/**
 * Tauri invoke 统一封装（前端契约唯一事实源，见 CONTRACT §3 / §4）
 * - invoke 名与参数键名逐字对应 Rust #[tauri::command]（snake_case）
 * - call() 统一把错误码映射为中文文案（§19 T4.5）后以 VaultError 抛出
 * - 另含：密码强度校验、答案规范化、默认保险箱路径、剪贴板、时间格式化
 */
import { invoke } from '@tauri-apps/api/core'
import { appDataDir, join } from '@tauri-apps/api/path'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import type {
  AppInfo,
  ConflictChoice,
  ItemDetailDto,
  ItemSummaryDto,
  RemoteTestResult,
  ServerCfg,
  SyncResult,
} from '../types'

/* ============ 错误码 -> 中文文案（§19 T4.5） ============ */
const ERROR_TEXT: Record<string, string> = {
  wrong_password: '密码错误',
  answer_wrong: '答案不正确',
  corrupt: '文件已损坏或被篡改可尝试恢复备份',
  not_found: '不存在',
  already_exists: '已存在保险箱',
  not_unlocked: '未解锁',
  weak_password: '密码强度不足',
  conflict: '条目在别处被修改',
  unreachable: '无法连接服务器',
  tls_error: '证书无效',
  unauthorized: '登录已过期',
  bad_request: '请求不合法',
  internal: '内部错误',
}

/** 带错误码的领域错误：message 已是可直接展示的中文 */
export class VaultError extends Error {
  code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'VaultError'
    this.code = code
  }
}

/** 从 Tauri reject 值中尽力提取错误码 */
function extractCode(e: unknown): string {
  if (e && typeof e === 'object') {
    const o = e as { code?: unknown; message?: unknown }
    if (typeof o.code === 'string' && o.code) return o.code
    // Rust 端可能把 VaultErrorDto JSON 字符串化后整体作为 message 抛出
    if (typeof o.message === 'string') {
      try {
        const parsed = JSON.parse(o.message) as { code?: unknown }
        if (parsed && typeof parsed.code === 'string' && parsed.code) return parsed.code
      } catch {
        /* 非 JSON 则忽略 */
      }
    }
  }
  if (typeof e === 'string') {
    try {
      const parsed = JSON.parse(e) as { code?: unknown }
      if (parsed && typeof parsed.code === 'string' && parsed.code) return parsed.code
    } catch {
      /* 忽略 */
    }
  }
  return 'internal'
}

/** 错误码文案（未知码返回"内部错误"，绝不泄露底层细节） */
export function errorTextFor(code: string): string {
  return ERROR_TEXT[code] ?? '内部错误'
}

/** 把任意未知错误转成 VaultError（保留原始 message 以便排查） */
export function toVaultError(e: unknown): VaultError {
  if (e instanceof VaultError) return e
  const code = extractCode(e)
  if (code === 'internal') {
    const raw = e instanceof Error ? e.message : String(e ?? '')
    return new VaultError(code, raw && raw !== 'undefined' ? raw : '内部错误')
  }
  return new VaultError(code, errorTextFor(code))
}

/** invoke 统一入口：reject 一律转成带中文文案的 VaultError */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args)
  } catch (e) {
    throw toVaultError(e)
  }
}

/* ============ CONTRACT §3 命令封装（逐字对应） ============ */

/** 连通自检 */
export function ping(): Promise<string> {
  return call<string>('ping')
}

/** 关于信息 */
export function appInfo(): Promise<AppInfo> {
  return call<AppInfo>('app_info')
}

/** 初始化本地保险箱（dir 目录下创建 vault.vault）；成功即解锁，返回全量明文摘要 */
export function initLocal(
  dir: string,
  password: string,
  question: string | null,
  answer: string | null,
): Promise<ItemSummaryDto[]> {
  return call<ItemSummaryDto[]>('init_local', { dir, password, question, answer })
}

/** 解锁本地保险箱：返回全量明文摘要 */
export function unlockLocal(path: string, password: string): Promise<ItemSummaryDto[]> {
  return call<ItemSummaryDto[]>('unlock_local', { path, password })
}

/** 立即锁定（清空内存明文与密钥） */
export function lockVault(): Promise<null> {
  return call<null>('lock')
}

/** 立即保存（本地模式把内存库写回容器文件） */
export function flushNow(): Promise<null> {
  return call<null>('flush_now')
}

/** 新建条目 */
export function itemCreate(input: {
  kind: number
  title: string
  content: string
  note?: string | null
}): Promise<ItemSummaryDto> {
  return call<ItemSummaryDto>('item_create', {
    kind: input.kind,
    title: input.title,
    content: input.content,
    note: input.note ?? null,
  })
}

/** 更新条目（kind 不可变，与 CONTRACT 参数一致） */
export function itemUpdate(input: {
  id: string
  title: string
  content: string
  note?: string | null
}): Promise<null> {
  return call<null>('item_update', {
    id: input.id,
    title: input.title,
    content: input.content,
    note: input.note ?? null,
  })
}

/** 删除条目 */
export function itemDelete(id: string): Promise<null> {
  return call<null>('item_delete', { id })
}

/** 取条目解密详情 */
export function itemGet(id: string): Promise<ItemDetailDto> {
  return call<ItemDetailDto>('item_get', { id })
}

/** 全量条目摘要列表 */
export function itemList(): Promise<ItemSummaryDto[]> {
  return call<ItemSummaryDto[]>('item_list')
}

/** 修改密码（需已解锁） */
export function changePassword(current: string, newPassword: string): Promise<null> {
  return call<null>('change_password', { current, new_password: newPassword })
}

/** 忘记密码：用保护问题答案重置本地保险箱密码 */
export function recoverReset(path: string, answer: string, newPassword: string): Promise<null> {
  return call<null>('recover_reset', { path, answer, new_password: newPassword })
}

/** 远程连接测试 */
export function remoteTest(cfg: ServerCfg): Promise<RemoteTestResult> {
  return call<RemoteTestResult>('remote_test', {
    address: cfg.address,
    port: cfg.port,
    https: cfg.https,
  })
}

/** 远程注册 */
export function remoteRegister(input: ServerCfg & {
  username: string
  password: string
  question?: string | null
  answer?: string | null
}): Promise<null> {
  return call<null>('remote_register', {
    address: input.address,
    port: input.port,
    https: input.https,
    username: input.username,
    password: input.password,
    question: input.question ?? null,
    answer: input.answer ?? null,
  })
}

/** 远程登录：返回全量摘要 */
export function remoteLogin(input: ServerCfg & {
  username: string
  password: string
}): Promise<ItemSummaryDto[]> {
  return call<ItemSummaryDto[]>('remote_login', {
    address: input.address,
    port: input.port,
    https: input.https,
    username: input.username,
    password: input.password,
  })
}

/** 远程登出 */
export function remoteLogout(): Promise<null> {
  return call<null>('remote_logout')
}

/** 手动同步（仅远程模式） */
export function syncNow(): Promise<SyncResult> {
  return call<SyncResult>('sync_now')
}

/**
 * 冲突三选一。当前契约 sync_now 只返回冲突计数、不暴露逐条 id，
 * 故约定 id='*' 表示"处理全部冲突"（由 Rust 端统一按 choice 应用）；
 * 未来若后端下发冲突 id 列表，前端会改为逐条调用。
 */
export function syncConflictResolve(id: string, choice: ConflictChoice): Promise<null> {
  return call<null>('sync_conflict_resolve', { id, choice })
}

/* ============ 本地保险箱路径约定 ============
 * 契约：初始化参数 dir 为"数据目录"，保险箱文件名为其下 vault.vault；
 * 前端默认取 Tauri 应用数据目录下的 data 子目录，即
 *   目录 = <appDataDir>/data
 *   文件 = <appDataDir>/data/vault.vault
 * （与契约"文件 data/vault.vault"表述一致；自定义目录选择需 dialog 插件，留待后续）
 * ============================================ */

/** 默认数据目录（非 Tauri 运行时报错则退回相对目录，便于浏览器联调） */
export async function defaultVaultDir(): Promise<string> {
  try {
    const base = await appDataDir()
    return await join(base, 'data')
  } catch {
    return 'data'
  }
}

/** 保险箱文件全路径：<dir>/vault.vault */
export async function vaultPathOf(dir: string): Promise<string> {
  return join(dir, 'vault.vault')
}

/** 默认保险箱文件全路径 */
export async function defaultVaultPath(): Promise<string> {
  return vaultPathOf(await defaultVaultDir())
}

/** 由文件全路径反推所在目录（去掉最后一段） */
export function vaultDirOf(path: string): string {
  const idx = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'))
  return idx > 0 ? path.slice(0, idx) : path
}

/* ============ 密码强度（与 Rust 端一致：>=10 位、非纯数字、非弱口令清单） ============ */

/** 内置弱口令清单（与后端共用同一子集，详见 CONTRACT §1） */
export const WEAK_PASSWORDS: string[] = [
  '1234567890',
  '123456789',
  'password',
  '1111111111',
  '0000000000',
  'iloveyou',
  'qwertyuiop',
  '12345678901',
  '1111222233',
  '1231231231',
  '1122334455',
  'a123456789',
]

export interface PasswordCheck {
  ok: boolean
  reason: string
}

/** 强度校验：长度 >= 10、非纯数字、非常见弱口令 */
export function checkPasswordStrength(pw: string): PasswordCheck {
  if (pw.length < 10) return { ok: false, reason: '密码至少需要 10 位' }
  if (/^\d+$/.test(pw)) return { ok: false, reason: '密码不能是纯数字' }
  if (/^(\d)\1{9,}$/.test(pw)) return { ok: false, reason: '密码过于简单，请避免重复数字' }
  const lower = pw.toLowerCase()
  if (WEAK_PASSWORDS.includes(lower)) {
    return { ok: false, reason: '该密码在常见弱口令清单中，请更换' }
  }
  return { ok: true, reason: '' }
}

/** 强度打分 0~4（用于强度计展示，仅供提示，判定以 checkPasswordStrength 为准） */
export function scorePassword(pw: string): number {
  let score = 0
  if (pw.length >= 10) score += 1
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 1
  if (/\d/.test(pw)) score += 1
  if (/[^A-Za-z0-9]/.test(pw)) score += 1
  return score
}

/** 保护问题答案规范化：NFKC + trim + 全小写（Rust 端不处理，调用方先规范化） */
export function normalizeAnswer(answer: string): string {
  return answer.normalize('NFKC').trim().toLowerCase()
}

/** 答案最小长度校验（提示用短语而非单词） */
export function checkAnswer(answer: string): PasswordCheck {
  const a = normalizeAnswer(answer)
  if (a.length < 8) return { ok: false, reason: '答案至少 8 个字符，建议用短语而非单词' }
  return { ok: true, reason: '' }
}

/* ============ 剪贴板（写入后由页面 60s 定时清空） ============ */

/** 写入剪贴板：优先 Tauri 剪贴板插件，浏览器环境降级 navigator */
export async function copyTextToClipboard(text: string): Promise<void> {
  try {
    await writeText(text)
  } catch {
    await navigator.clipboard.writeText(text)
  }
}

/** 主动清空剪贴板（自动锁定/定时器到期时调用） */
export async function clearClipboard(): Promise<void> {
  try {
    await writeText('')
  } catch {
    /* 忽略 */
  }
}

/* ============ 时间格式化 ============ */

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n)
}

/** epoch 毫秒 -> "yyyy/M/d HH:mm" */
export function fmtTime(ms: number): string {
  const d = new Date(ms)
  return `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** epoch 毫秒 -> 相对时间（"刚刚 / n 分钟前 / n 小时前 / n 天前 / 日期"） */
export function fmtAgo(ms: number): string {
  const diff = Date.now() - ms
  if (diff < 60_000) return '刚刚'
  const min = Math.floor(diff / 60_000)
  if (min < 60) return `${min} 分钟前`
  const hour = Math.floor(min / 60)
  if (hour < 24) return `${hour} 小时前`
  const day = Math.floor(hour / 24)
  if (day < 7) return `${day} 天前`
  return fmtTime(ms)
}
