/**
 * VaultBox 全局状态（Pinia）
 * 契约状态：{ mode, unlocked, summaries, detail, busy, syncState }
 * 另持久化 UI 偏好：theme / autoLockMinutes / serverCfg / mode
 */
import { defineStore } from 'pinia'
import type { ConflictChoice, ItemDetailDto, ItemSummaryDto, Mode, ServerCfg, SyncState } from '../types'
import {
  checkPasswordStrength,
  clearClipboard,
  defaultVaultDir,
  defaultVaultPath,
  itemDelete,
  itemGet,
  itemList,
  itemUpdate,
  itemCreate,
  initLocal as apiInitLocal,
  lockVault,
  normalizeAnswer,
  recoverReset as apiRecoverReset,
  remoteLogin as apiRemoteLogin,
  remoteRegister as apiRemoteRegister,
  remoteTest as apiRemoteTest,
  remoteLogout as apiRemoteLogout,
  changePassword as apiChangePassword,
  syncNow as apiSyncNow,
  syncConflictResolve as apiSyncConflictResolve,
  unlockLocal as apiUnlockLocal,
  vaultDirOf,
  vaultPathOf,
  type VaultError,
} from '../composables/useVault'

/** localStorage 键名（index.html 内联脚本同步使用 vaultbox:theme） */
const LS_THEME = 'vaultbox:theme'
const LS_MODE = 'vaultbox:mode'
const LS_AUTOLOCK = 'vaultbox:autolock'
const LS_SERVER = 'vaultbox:server'

function lsGet(key: string): string | null {
  try {
    return localStorage.getItem(key)
  } catch {
    return null
  }
}
function lsSet(key: string, value: string): void {
  try {
    localStorage.setItem(key, value)
  } catch {
    /* 忽略 */
  }
}

/** 动作统一返回体：成功 ok=true；失败 ok=false 并携带中文 message 与错误码 */
export interface ActionResult {
  ok: boolean
  code?: string
  message: string
}

/** 远程登录/注册所需的完整表单（含服务器配置与凭据） */
export interface RemoteForm {
  address: string
  port: number
  https: boolean
  username: string
  password: string
  question?: string | null
  answer?: string | null
}

function toActionResult(e: unknown): ActionResult {
  const ve = e as VaultError
  const code = ve?.code ?? 'internal'
  const message = ve?.message ?? '内部错误'
  return { ok: false, code, message }
}

export const useVaultStore = defineStore('vault', {
  state: () => {
    const storedMode = lsGet(LS_MODE)
    const mode: Mode = storedMode === 'local' || storedMode === 'remote' ? storedMode : null
    const storedAutolock = Number(lsGet(LS_AUTOLOCK) ?? '')
    const autolock = Number.isFinite(storedAutolock) && storedAutolock >= 0 ? storedAutolock : 5
    let theme: 'light' | 'dark' = 'light'
    if (lsGet(LS_THEME) === 'dark') theme = 'dark'
    let serverCfg: ServerCfg = { address: '127.0.0.1', port: 3000, https: false }
    try {
      const raw = lsGet(LS_SERVER)
      if (raw) {
        const parsed = JSON.parse(raw) as Partial<ServerCfg>
        serverCfg = {
          address: typeof parsed.address === 'string' && parsed.address ? parsed.address : serverCfg.address,
          port:
            typeof parsed.port === 'number' && parsed.port > 0 && parsed.port < 65536
              ? parsed.port
              : serverCfg.port,
          https: typeof parsed.https === 'boolean' ? parsed.https : serverCfg.https,
        }
      }
    } catch {
      /* 解析失败用默认 */
    }
    return {
      mode,
      unlocked: false,
      /** 发行版形态：full 完整版 / store 微软商店版（纯本地，隐藏联网入口） */
      edition: 'full' as 'full' | 'store',
      /** 本地保险箱所在目录与文件全路径（local 模式） */
      vaultDir: '',
      vaultPath: '',
      summaries: [] as ItemSummaryDto[],
      detail: null as ItemDetailDto | null,
      busy: false,
      syncState: { state: 'idle', conflicts: [] } as SyncState,
      theme,
      autoLockMinutes: autolock,
      serverCfg,
    }
  },

  getters: {
    /** 条目总数 */
    totalCount: (s) => s.summaries.length,
    /** 按类型计数（kind: 0 账号 1 备注 2 密钥） */
    kindCount:
      (s) =>
      (kind: number): number =>
        s.summaries.filter((i) => i.kind === kind).length,
  },

  actions: {
    /* ---------- 主题 / 偏好 ---------- */

    /** 启动时读取应用信息（版本号 + 发行版形态 full/store） */
    async loadAppInfo() {
      try {
        const { appInfo } = await import('../composables/useVault')
        const info = await appInfo()
        this.edition = info.edition === 'store' ? 'store' : 'full'
      } catch {
        this.edition = 'full'
      }
    },

    /** 依据当前 theme 切换 html.dark */
    applyTheme() {
      document.documentElement.classList.toggle('dark', this.theme === 'dark')
    },

    setTheme(theme: 'light' | 'dark') {
      this.theme = theme
      lsSet(LS_THEME, theme)
      this.applyTheme()
    },

    setAutoLockMinutes(minutes: number) {
      this.autoLockMinutes = minutes
      lsSet(LS_AUTOLOCK, String(minutes))
    },

    setServerCfg(cfg: ServerCfg) {
      this.serverCfg = { ...cfg }
      lsSet(LS_SERVER, JSON.stringify(cfg))
    },

    persistMode() {
      lsSet(LS_MODE, this.mode ?? '')
    },

    /* ---------- 初始化 / 解锁 ---------- */

    /** 初始化本地保险箱（成功后即解锁进入主页，后端直接返回全量摘要） */
    async initLocal(
      password: string,
      question: string | null,
      answer: string | null,
    ): Promise<ActionResult> {
      this.busy = true
      try {
        const dir = await defaultVaultDir()
        const normAnswer = answer ? normalizeAnswer(answer) : null
        const list = await apiInitLocal(dir, password, question || null, normAnswer)
        this.vaultDir = dir
        this.vaultPath = await vaultPathOf(dir)
        this.mode = 'local'
        this.persistMode()
        this.unlocked = true
        this.detail = null
        this.summaries = list
        return { ok: true, message: '保险箱已创建' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 注册远程账户（注册成功后需再登录进入主页） */
    async registerRemote(form: RemoteForm): Promise<ActionResult> {
      this.busy = true
      try {
        const cfg: ServerCfg = { address: form.address, port: form.port, https: form.https }
        await apiRemoteRegister({
          ...cfg,
          username: form.username,
          password: form.password,
          question: form.question ?? null,
          answer: form.answer ? normalizeAnswer(form.answer) : null,
        })
        this.setServerCfg(cfg)
        this.mode = 'remote'
        this.persistMode()
        this.unlocked = false
        return { ok: true, message: '注册成功' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 解锁本地保险箱（默认路径） */
    async unlockLocal(password: string): Promise<ActionResult> {
      this.busy = true
      try {
        const path = await defaultVaultPath()
        const list = await apiUnlockLocal(path, password)
        this.vaultPath = path
        this.vaultDir = vaultDirOf(path)
        this.mode = 'local'
        this.persistMode()
        this.unlocked = true
        this.summaries = list
        this.detail = null
        this.syncState = { state: 'idle', conflicts: [] }
        return { ok: true, message: '解锁成功' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 远程登录（成功后全量拉取并进入主页） */
    async loginRemote(form: RemoteForm): Promise<ActionResult> {
      this.busy = true
      try {
        const cfg: ServerCfg = { address: form.address, port: form.port, https: form.https }
        const list = await apiRemoteLogin({
          ...cfg,
          username: form.username,
          password: form.password,
        })
        this.setServerCfg(cfg)
        this.mode = 'remote'
        this.persistMode()
        this.unlocked = true
        this.summaries = list
        this.detail = null
        this.syncState = { state: 'idle', conflicts: [] }
        return { ok: true, message: '登录成功' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 远程连接测试（不改会话状态） */
    async testRemote(cfg: ServerCfg) {
      return apiRemoteTest(cfg)
    },

    /** 立即锁定：清空内存明文与剪贴板 */
    async lock() {
      if (this.busy || !this.unlocked) return
      this.unlocked = false
      try {
        await lockVault()
      } catch {
        /* 后端锁定失败也照常清空本地态 */
      }
      this.summaries = []
      this.detail = null
      this.syncState = { state: 'idle', conflicts: [] }
      await clearClipboard()
    },

    /** 远程登出（仅清后端会话；模式保留） */
    async logoutRemote(): Promise<void> {
      try {
        await apiRemoteLogout()
      } catch {
        /* 忽略 */
      }
      this.unlocked = false
      this.summaries = []
      this.detail = null
    },

    /* ---------- 条目 CRUD ---------- */

    /** 重新拉取列表（调用前应已解锁） */
    async refreshSummaries(): Promise<void> {
      this.summaries = await itemList()
    },

    /** 拉取条目解密详情 */
    async openDetail(id: string): Promise<void> {
      this.detail = await itemGet(id)
    },

    /** 新建条目并刷新列表 */
    async createItem(input: {
      kind: number
      title: string
      content: string
      note?: string | null
    }): Promise<ActionResult> {
      this.busy = true
      try {
        await itemCreate(input)
        await this.refreshSummaries()
        return { ok: true, message: '已保存' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 编辑条目：更新后刷新列表，若正展示该条目则一并刷新详情 */
    async updateItem(input: {
      id: string
      title: string
      content: string
      note?: string | null
    }): Promise<ActionResult> {
      this.busy = true
      try {
        await itemUpdate(input)
        await this.refreshSummaries()
        if (this.detail && this.detail.id === input.id) {
          this.detail = await itemGet(input.id)
        }
        return { ok: true, message: '已更新' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 删除条目 */
    async deleteItem(id: string): Promise<ActionResult> {
      this.busy = true
      try {
        await itemDelete(id)
        this.summaries = this.summaries.filter((i) => i.id !== id)
        if (this.detail && this.detail.id === id) this.detail = null
        return { ok: true, message: '已删除' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /* ---------- 改密 / 恢复 ---------- */

    /** 修改密码（需解锁，前后端双重强度校验） */
    async changePassword(current: string, newPassword: string): Promise<ActionResult> {
      const check = checkPasswordStrength(newPassword)
      if (!check.ok) return { ok: false, code: 'weak_password', message: check.reason }
      this.busy = true
      try {
        await apiChangePassword(current, newPassword)
        return { ok: true, message: '密码已修改' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /** 忘记密码重置（答案规范化后交给后端） */
    async recover(answer: string, newPassword: string): Promise<ActionResult> {
      const check = checkPasswordStrength(newPassword)
      if (!check.ok) return { ok: false, code: 'weak_password', message: check.reason }
      this.busy = true
      try {
        const path = await defaultVaultPath()
        await apiRecoverReset(path, normalizeAnswer(answer), newPassword)
        return { ok: true, message: '已重置，请用新密码解锁' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },

    /* ---------- 同步（仅远程模式） ---------- */

    /** 手动同步；conflicts>0 时由页面弹冲突选择 */
    async runSync(): Promise<{ ok: boolean; pulled?: number; pushed?: number; conflicts?: number; message?: string }> {
      if (this.mode !== 'remote') return { ok: false, message: '当前不是联网模式' }
      this.syncState = { state: 'syncing', conflicts: [] }
      try {
        const res = await apiSyncNow()
        this.syncState = { state: 'synced', conflicts: [] }
        try {
          await this.refreshSummaries()
        } catch {
          /* 列表刷新失败不影响同步结果展示 */
        }
        return { ok: true, pulled: res.pulled, pushed: res.pushed, conflicts: res.conflicts }
      } catch (e) {
        const r = toActionResult(e)
        this.syncState = { state: 'error', conflicts: [] }
        return { ok: false, message: r.message }
      }
    },

    /**
     * 冲突三选处理：逐条（若后端下发了 id）或全量（id='*'）调用
     * sync_conflict_resolve，随后再同步一次收尾并刷新列表。
     */
    async resolveConflicts(choice: ConflictChoice): Promise<ActionResult> {
      this.busy = true
      try {
        const ids = this.syncState.conflicts.length > 0 ? this.syncState.conflicts : ['*']
        for (const id of ids) {
          await apiSyncConflictResolve(id, choice)
        }
        // 收尾同步：拉取服务器合并结果
        try {
          const res = await apiSyncNow()
          this.syncState = { state: 'synced', conflicts: [] }
          if (res.conflicts > 0) {
            return { ok: false, code: 'conflict', message: `仍有 ${res.conflicts} 个冲突未解决，请再次选择处理方式` }
          }
        } catch {
          /* 收尾同步失败不阻断提示成功 */
        }
        try {
          await this.refreshSummaries()
        } catch {
          /* 忽略 */
        }
        return { ok: true, message: '冲突已处理' }
      } catch (e) {
        return toActionResult(e)
      } finally {
        this.busy = false
      }
    },
  },
})
