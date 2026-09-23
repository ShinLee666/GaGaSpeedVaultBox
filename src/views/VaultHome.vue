<script setup lang="ts">
/**
 * /vault —— 保险箱主页（登录后唯一主界面，§7.3 线框）
 * 布局：顶栏（品牌/搜索/同步/设置/锁定）+
 *       左侧分类栏（全部/账号/备注/密钥 + 新建）
 *       + 条目列表（卡片） + 详情/编辑（密文默认掩码、复制 60s 清空）
 * 联网模式：手动同步按钮 + 冲突三选弹窗
 */
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import {
  ElMessage,
  ElMessageBox,
  type FormInstance,
  type FormRules,
} from 'element-plus'
import {
  Lock,
  Setting,
  Search,
  Plus,
  Refresh,
  User,
  Document,
  Key,
  View,
  Hide,
  CopyDocument,
  Delete,
  EditPen,
  WarningFilled,
} from '@element-plus/icons-vue'
import type { Component } from 'vue'
import { useVaultStore } from '../stores/vault'
import { useAutoLock } from '../composables/useAutoLock'
import {
  copyTextToClipboard,
  clearClipboard,
  fmtAgo,
  fmtTime,
} from '../composables/useVault'
import { kindLabel } from '../types'
import type { ConflictChoice, ItemDetailDto, ItemSummaryDto } from '../types'

const router = useRouter()
const store = useVaultStore()
// 空闲 5 分钟自动锁定（时长可在设置页调整）
const { lockNow } = useAutoLock()

/* ================= 顶栏 / 列表 ================= */

/** 当前分类过滤：null=全部 */
const filterKind = ref<number | null>(null)
const search = ref('')

/** 相对时间刻度：每分钟刷新一次"xx 分钟前" */
const nowTick = ref(Date.now())
let tickTimer: number | undefined

const sidebarItems = computed(() => [
  { key: null, label: '全部', count: store.totalCount },
  { key: 0, label: '账号', count: store.kindCount(0) },
  { key: 1, label: '备注', count: store.kindCount(1) },
  { key: 2, label: '密钥', count: store.kindCount(2) },
])

/** 搜索（前端过滤 title 与类型中文名）+ 分类过滤 */
const filteredList = computed<ItemSummaryDto[]>(() => {
  const kw = search.value.trim().toLowerCase()
  return store.summaries.filter((i) => {
    if (filterKind.value !== null && i.kind !== filterKind.value) return false
    if (!kw) return true
    return i.title.toLowerCase().includes(kw) || kindLabel(i.kind).includes(kw)
  })
})

const KIND_ICONS: Record<number, Component> = {
  0: User,
  1: Document,
  2: Key,
}
const KIND_COLORS: Record<number, string> = {
  0: 'var(--vb-brand)',
  1: 'var(--el-color-success)',
  2: 'var(--vb-brand-2)',
}

/** 复制倒计时（秒），0 表示无进行中倒计时 */
const copyLeft = ref(0)
let copyTimer: number | undefined

/* ================= 详情 ================= */

const loadingDetail = ref(false)
/** 详情内容是否明文显示（默认掩码） */
const reveal = ref(false)

/** 列表选中条目 */
const activeId = ref<string>('')

async function selectItem(item: ItemSummaryDto) {
  if (loadingDetail.value) return
  activeId.value = item.id
  reveal.value = false
  loadingDetail.value = true
  try {
    await store.openDetail(item.id)
  } catch (e) {
    ElMessage.error((e as Error).message || '读取条目失败')
  } finally {
    loadingDetail.value = false
  }
}

/** 复制内容 -> 60s 后自动清空剪贴板（§6.4） */
async function copyContent() {
  const content = store.detail?.content
  if (!content) return
  await copyTextToClipboard(content)
  copyLeft.value = 60
  ElMessage.success('已复制到剪贴板，60 秒后将自动清空')
  if (copyTimer !== undefined) window.clearInterval(copyTimer)
  copyTimer = window.setInterval(() => {
    copyLeft.value -= 1
    if (copyLeft.value <= 0) {
      if (copyTimer !== undefined) {
        window.clearInterval(copyTimer)
        copyTimer = undefined
      }
      void clearClipboard()
      ElMessage({ type: 'info', message: '剪贴板已自动清空', duration: 2000 })
    }
  }, 1000)
}

function maskText(t: string): string {
  return '•'.repeat(Math.min(24, Math.max(8, t.length)))
}

/* ================= 新建 / 编辑弹窗 ================= */

interface ItemForm {
  kind: number
  title: string
  content: string
  note: string
}

const dlgVisible = ref(false)
const dlgMode = ref<'create' | 'edit'>('create')
const dlgSubmitting = ref(false)
const dlgFormRef = ref<FormInstance>()
const dlgMask = ref(true) // 敏感内容掩码（默认开）

function emptyForm(): ItemForm {
  return {
    kind: filterKind.value ?? 0,
    title: '',
    content: '',
    note: '',
  }
}
const dlgForm = reactive<ItemForm>(emptyForm())

const dlgTitle = computed(() => (dlgMode.value === 'create' ? '新建条目' : '编辑条目'))

const dlgRules = reactive<FormRules<ItemForm>>({
  title: [
    {
      validator: (_r, v: string, cb) => {
        if (!v.trim() && !dlgForm.content.trim()) cb(new Error('标题与内容至少填写一项'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
  content: [
    {
      validator: (_r, v: string, cb) => {
        if (!v.trim() && !dlgForm.title.trim()) cb(new Error('标题与内容至少填写一项'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
})

/** 新建 */
function openCreate() {
  dlgMode.value = 'create'
  Object.assign(dlgForm, emptyForm())
  dlgMask.value = true
  dlgVisible.value = true
}

/** 编辑（kind 不可变，与 item_update 参数一致） */
function openEdit() {
  const d = store.detail
  if (!d) return
  dlgMode.value = 'edit'
  Object.assign(dlgForm, {
    kind: d.kind,
    title: d.title,
    content: d.content,
    note: d.note ?? '',
  })
  dlgMask.value = true
  dlgVisible.value = true
}

async function saveDialog() {
  const valid = await dlgFormRef.value?.validate().catch(() => false)
  if (!valid || dlgSubmitting.value) return
  dlgSubmitting.value = true
  const payload = {
    title: dlgForm.title.trim(),
    content: dlgForm.content,
    note: dlgForm.note.trim() || null,
  }
  if (dlgMode.value === 'create') {
    const res = await store.createItem({ kind: dlgForm.kind, ...payload })
    if (res.ok) {
      ElMessage.success('已保存')
      dlgVisible.value = false
    } else ElMessage.error(res.message)
  } else if (store.detail) {
    const res = await store.updateItem({ id: store.detail.id, ...payload })
    if (res.ok) {
      ElMessage.success('已更新')
      dlgVisible.value = false
    } else ElMessage.error(res.message)
  }
  dlgSubmitting.value = false
}

/** 删除（二次确认） */
async function doDelete() {
  if (!store.detail) return
  const res = await store.deleteItem(store.detail.id)
  if (res.ok) ElMessage.success('已删除')
  else ElMessage.error(res.message)
}

/* ================= 同步（联网模式） ================= */

const syncing = ref(false)
const conflictVisible = ref(false)
const conflictCount = ref(0)
const conflictChoice = ref<ConflictChoice>('server')

const syncTag = computed(() => {
  switch (store.syncState.state) {
    case 'syncing':
      return { type: 'primary' as const, text: '同步中…' }
    case 'synced':
      return { type: 'success' as const, text: '已同步' }
    case 'error':
      return { type: 'danger' as const, text: '同步出错' }
    default:
      return { type: 'info' as const, text: '待同步' }
  }
})

const CONFLICT_OPTIONS: { value: ConflictChoice; label: string; desc: string }[] = [
  { value: 'local', label: '以本地为准', desc: '保留本机修改，覆盖服务器版本' },
  { value: 'server', label: '以服务器为准', desc: '丢弃本机修改，改用服务器版本' },
  { value: 'copy', label: '复制为新条目', desc: '保留双方，服务器版本复制为一条新记录' },
]

async function doSync() {
  if (syncing.value) return
  syncing.value = true
  const res = await store.runSync()
  syncing.value = false
  if (!res.ok) {
    ElMessage.error(res.message ?? '同步失败')
    return
  }
  const parts = [`拉取 ${res.pulled ?? 0}`, `推送 ${res.pushed ?? 0}`]
  const conflicts = res.conflicts ?? 0
  ElMessage.success(`同步完成：${parts.join(' / ')}`)
  if (conflicts > 0) {
    conflictCount.value = conflicts
    conflictChoice.value = 'server'
    conflictVisible.value = true
  }
}

async function confirmResolve() {
  if (conflictVisible.value) conflictVisible.value = false
  const res = await store.resolveConflicts(conflictChoice.value)
  if (res.ok) {
    ElMessage.success(res.message)
  } else {
    ElMessage.error(res.message)
  }
}

/** 锁定确认 */
async function manualLock() {
  try {
    await ElMessageBox.confirm('锁定后需要重新输入密码才能查看内容，确定锁定？', '锁定保险箱', {
      confirmButtonText: '立即锁定',
      cancelButtonText: '取消',
      type: 'warning',
    })
    await lockNow()
  } catch {
    /* 用户取消 */
  }
}

/* ================= 生命周期 ================= */

watch(
  () => store.detail?.id,
  () => {
    reveal.value = false
  },
)

// 会话意外被锁（如设置页触发）时兜底跳回解锁页
watch(
  () => store.unlocked,
  (u) => {
    if (!u) router.push('/unlock')
  },
)

onMounted(() => {
  tickTimer = window.setInterval(() => {
    nowTick.value = Date.now()
  }, 60_000)
})

onBeforeUnmount(() => {
  if (tickTimer !== undefined) window.clearInterval(tickTimer)
  if (copyTimer !== undefined) window.clearInterval(copyTimer)
})
</script>

<template>
  <div class="home">
    <!-- ============ 顶栏 ============ -->
    <header class="topbar">
      <div class="brand">
        <div class="brand__logo">
          <el-icon :size="15"><Lock /></el-icon>
        </div>
        <span class="brand__name">VaultBox</span>
        <el-tag size="small" :type="store.mode === 'remote' ? 'primary' : 'success'" effect="light" round>
          {{ store.mode === 'remote' ? '联网模式' : '本地模式' }}
        </el-tag>
      </div>

      <div class="topbar__search">
        <el-input v-model="search" clearable placeholder="搜索标题或类型…" size="default">
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>
      </div>

      <div class="topbar__actions">
        <!-- 联网模式：同步状态 + 同步按钮 -->
        <template v-if="store.mode === 'remote'">
          <el-tag :type="syncTag.type" size="small" effect="dark">{{ syncTag.text }}</el-tag>
          <el-button size="small" type="primary" plain :loading="syncing" @click="doSync">
            <el-icon style="margin-right: 4px"><Refresh /></el-icon>同步
          </el-button>
        </template>

        <el-tooltip content="设置" placement="bottom">
          <el-button size="small" circle @click="router.push('/settings')">
            <el-icon><Setting /></el-icon>
          </el-button>
        </el-tooltip>
        <el-tooltip content="立即锁定" placement="bottom">
          <el-button size="small" circle type="danger" plain @click="manualLock">
            <el-icon><Lock /></el-icon>
          </el-button>
        </el-tooltip>
      </div>
    </header>

    <!-- ============ 主体三栏 ============ -->
    <div class="body">
      <!-- 左侧：新建 + 分类 -->
      <aside class="side">
        <el-button type="primary" class="new-btn" @click="openCreate">
          <el-icon><Plus /></el-icon>新建条目
        </el-button>
        <nav class="side__nav">
          <div
            v-for="it in sidebarItems"
            :key="String(it.key)"
            class="side__item"
            :class="{ active: filterKind === it.key }"
            @click="filterKind = it.key"
          >
            <span>{{ it.label }}</span>
            <span class="side__count">{{ it.count }}</span>
          </div>
        </nav>
        <div class="side__foot">
          <div class="side__meta">共 {{ store.totalCount }} 条记录</div>
          <div v-if="store.mode === 'local' && store.vaultPath" class="side__meta mono" :title="store.vaultPath">
            本地文件：data/vault.vault
          </div>
          <div v-else-if="store.mode === 'remote'" class="side__meta mono" :title="`${store.serverCfg.https ? 'https' : 'http'}://${store.serverCfg.address}:${store.serverCfg.port}`">
            {{ store.serverCfg.address }}:{{ store.serverCfg.port }}
          </div>
        </div>
      </aside>

      <!-- 中间：条目列表 -->
      <section class="list">
        <div class="list__head">
          <span class="list__title">{{ sidebarItems.find((i) => i.key === filterKind)?.label ?? '全部' }}（{{ filteredList.length }}）</span>
        </div>
        <el-scrollbar class="list__scroll">
          <div v-if="filteredList.length === 0" class="list__empty">
            <el-empty :description="search ? '没有匹配的条目' : '这里还没有条目，点击左侧「新建条目」'" />
          </div>
          <div
            v-for="item in filteredList"
            :key="item.id"
            class="row"
            :class="{ active: item.id === activeId }"
            @click="selectItem(item)"
          >
            <el-icon class="row__icon" :style="{ color: KIND_COLORS[item.kind] ?? 'var(--vb-text-2)' }">
              <component :is="KIND_ICONS[item.kind] ?? Document" />
            </el-icon>
            <div class="row__main">
              <div class="row__title vb-ellipsis">{{ item.title || '（无标题）' }}</div>
              <div class="row__sub">
                <span>{{ kindLabel(item.kind) }}</span>
                <span>·</span>
                <span>{{ fmtAgo(item.updated_at) }}</span>
              </div>
            </div>
          </div>
        </el-scrollbar>
      </section>

      <!-- 右侧：详情 / 编辑 -->
      <section class="detail" v-loading="loadingDetail">
        <div v-if="!store.detail" class="detail__empty">
          <div class="detail__glyph">
            <el-icon :size="34"><Lock /></el-icon>
          </div>
          <p>选择左侧条目查看详情<br />或点击"新建条目"开始记录</p>
        </div>

        <div v-else class="detail__card">
          <div class="detail__head">
            <div class="detail__title-box">
              <el-tag size="small" round effect="plain">{{ kindLabel(store.detail.kind) }}</el-tag>
              <h3 class="detail__title">{{ store.detail.title || '（无标题）' }}</h3>
            </div>
            <div class="detail__ops">
              <el-button size="small" text @click="openEdit">
                <el-icon style="margin-right: 3px"><EditPen /></el-icon>编辑
              </el-button>
              <el-popconfirm title="删除后无法恢复，确定删除该条目？" confirm-button-text="删除" cancel-button-text="取消" confirm-button-type="danger" @confirm="doDelete">
                <template #reference>
                  <el-button size="small" text type="danger">
                    <el-icon style="margin-right: 3px"><Delete /></el-icon>删除
                  </el-button>
                </template>
              </el-popconfirm>
            </div>
          </div>

          <!-- 内容（默认掩码，可切换明文） -->
          <div class="detail__block">
            <div class="block__label">内容</div>
            <div class="content-box" :class="{ secret: store.detail.kind === 2 }">
              <div class="content-box__toolbar">
                <el-button size="small" text @click="reveal = !reveal">
                  <el-icon style="margin-right: 4px">
                    <View v-if="!reveal" />
                    <Hide v-else />
                  </el-icon>
                  {{ reveal ? '隐藏内容' : '显示明文' }}
                </el-button>
                <el-button size="small" text type="primary" :disabled="!store.detail.content" @click="copyContent">
                  <el-icon style="margin-right: 4px"><CopyDocument /></el-icon>
                  {{ copyLeft > 0 ? `复制（${copyLeft}s 后清空）` : '复制' }}
                </el-button>
              </div>
              <div v-if="store.detail.content" class="content-box__body" :class="{ masked: !reveal }">
                <span v-if="!reveal" class="vb-mono masked-text">{{ maskText(store.detail.content) }}</span>
                <span v-else class="vb-mono vb-secret">{{ store.detail.content }}</span>
              </div>
              <div v-else class="content-box__body muted">（无内容）</div>
            </div>
            <div v-if="copyLeft > 0" class="clip-hint">
              <el-icon><WarningFilled /></el-icon>&nbsp;内容已写入剪贴板，{{ copyLeft }} 秒后自动清空
            </div>
          </div>

          <!-- 备注 -->
          <div v-if="store.detail.note" class="detail__block">
            <div class="block__label">备注</div>
            <div class="note-box">{{ store.detail.note }}</div>
          </div>

          <div class="detail__meta">
            <span>创建于 {{ fmtTime(store.detail.created_at) }}</span>
            <span>更新于 {{ fmtTime(store.detail.updated_at) }}</span>
          </div>
        </div>
      </section>
    </div>

    <!-- ============ 新建 / 编辑弹窗 ============ -->
    <el-dialog
      v-model="dlgVisible"
      :title="dlgTitle"
      width="min(560px, 92vw)"
      :close-on-click-modal="false"
      destroy-on-close
      @closed="dlgVisible = false"
    >
      <el-form ref="dlgFormRef" :model="dlgForm" :rules="dlgRules" label-position="top">
        <el-form-item v-if="dlgMode === 'create'" label="类型" prop="kind">
          <el-select v-model="dlgForm.kind" style="width: 100%">
            <el-option v-for="o in [{ value: 0, label: '账号' }, { value: 1, label: '备注' }, { value: 2, label: '密钥' }]" :key="o.value" :value="o.value" :label="o.label" />
          </el-select>
        </el-form-item>
        <el-form-item v-else label="类型">
          <el-tag round effect="plain">{{ kindLabel(dlgForm.kind) }}（类型不可修改）</el-tag>
        </el-form-item>

        <el-form-item label="标题" prop="title">
          <el-input v-model="dlgForm.title" placeholder="给条目起个名字" maxlength="200" />
        </el-form-item>

        <el-form-item label="内容" prop="content">
          <el-input
            v-model="dlgForm.content"
            :type="dlgMask ? 'password' : 'textarea'"
            :rows="4"
            resize="vertical"
            autocomplete="off"
            :show-password="dlgForm.kind === 2"
            placeholder="账号/密码/密钥等敏感信息"
            class="vb-mono"
          />
        </el-form-item>
        <div v-if="dlgForm.content" class="mask-row">
          <el-checkbox v-model="dlgMask">输入时掩码显示（推荐）</el-checkbox>
        </div>

        <el-form-item label="备注">
          <el-input v-model="dlgForm.note" type="textarea" :rows="2" resize="vertical" placeholder="可选：使用场景、关联站点等" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dlgVisible = false">取消</el-button>
        <el-button type="primary" :loading="dlgSubmitting" @click="saveDialog">保存</el-button>
      </template>
    </el-dialog>

    <!-- ============ 冲突三选弹窗（联网模式） ============ -->
    <el-dialog
      v-model="conflictVisible"
      title="检测到同步冲突"
      width="min(520px, 92vw)"
      :close-on-click-modal="false"
    >
      <div class="conflict-tip">
        <el-icon :size="18" color="var(--el-color-warning)"><WarningFilled /></el-icon>
        <span>有 {{ conflictCount }} 个条目在本机与服务器上都被修改过，请选择处理方式：</span>
      </div>
      <el-radio-group v-model="conflictChoice" class="conflict-opts">
        <el-radio v-for="o in CONFLICT_OPTIONS" :key="o.value" :value="o.value" border class="conflict-opt">
          <div class="conflict-opt__title">{{ o.label }}</div>
          <div class="conflict-opt__desc">{{ o.desc }}</div>
        </el-radio>
      </el-radio-group>
      <template #footer>
        <el-button @click="conflictVisible = false">稍后处理</el-button>
        <el-button type="primary" @click="confirmResolve">确定处理</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.home {
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--vb-page-bg);
}

/* ---------- 顶栏 ---------- */
.topbar {
  height: 54px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 0 16px;
  background: var(--vb-card-bg);
  border-bottom: 1px solid var(--vb-border);
}

.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.brand__logo {
  width: 28px;
  height: 28px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  background: linear-gradient(135deg, var(--vb-brand), var(--vb-brand-2));
}

.brand__name {
  font-weight: 700;
  font-size: 15px;
  white-space: nowrap;
}

.topbar__search {
  flex: 1;
  max-width: 420px;
  min-width: 160px;
}

.topbar__actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: auto;
}

/* ---------- 主体 ---------- */
.body {
  flex: 1;
  min-height: 0;
  display: flex;
}

.side {
  width: 190px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  padding: 14px 12px;
  border-right: 1px solid var(--vb-border);
  background: var(--vb-card-bg);
}

.new-btn {
  width: 100%;
  margin-bottom: 14px;
}

.side__nav {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1;
  min-height: 0;
}

.side__item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-radius: 8px;
  font-size: 13.5px;
  cursor: pointer;
  color: var(--vb-text-1);
  transition: background 0.15s ease;
}

.side__item:hover {
  background: var(--vb-hover);
}

.side__item.active {
  background: color-mix(in srgb, var(--vb-brand) 12%, transparent);
  color: var(--vb-brand);
  font-weight: 600;
}

.side__count {
  font-size: 12px;
  color: var(--vb-text-2);
}

.side__item.active .side__count {
  color: var(--vb-brand);
}

.side__foot {
  border-top: 1px solid var(--vb-border);
  padding-top: 10px;
}

.side__meta {
  font-size: 11.5px;
  color: var(--vb-text-2);
  margin-top: 4px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.mono {
  font-family: Consolas, 'Courier New', monospace;
}

/* ---------- 列表 ---------- */
.list {
  width: 300px;
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
  border-right: 1px solid var(--vb-border);
}

.list__head {
  padding: 12px 14px 8px;
  font-size: 12px;
  color: var(--vb-text-2);
}

.list__scroll {
  flex: 1;
  min-height: 0;
  padding: 0 8px 8px;
}

.row {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  margin-bottom: 4px;
  border-radius: 10px;
  cursor: pointer;
  transition:
    background 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.row:hover {
  background: var(--vb-hover);
  transform: translateY(-1px);
}

.row.active {
  background: color-mix(in srgb, var(--vb-brand) 10%, transparent);
  box-shadow: inset 2px 0 0 var(--vb-brand);
}

.row__icon {
  font-size: 17px;
  flex-shrink: 0;
}

.row__main {
  min-width: 0;
  flex: 1;
}

.row__title {
  font-size: 13.5px;
  font-weight: 600;
}

.row__sub {
  font-size: 11.5px;
  color: var(--vb-text-2);
  display: flex;
  gap: 5px;
  margin-top: 2px;
}

.list__empty {
  padding: 40px 8px;
}

/* ---------- 详情 ---------- */
.detail {
  flex: 1;
  min-width: 0;
  display: flex;
  padding: 16px;
  overflow: auto;
}

.detail__empty {
  margin: auto;
  text-align: center;
  color: var(--vb-text-2);
  line-height: 1.8;
  font-size: 13px;
}

.detail__glyph {
  width: 74px;
  height: 74px;
  margin: 0 auto 16px;
  border-radius: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--vb-brand);
  background: color-mix(in srgb, var(--vb-brand) 10%, transparent);
}

.detail__card {
  width: 100%;
  max-width: 680px;
  margin: 0 auto;
  background: var(--vb-card-bg);
  border: 1px solid var(--vb-border);
  border-radius: 12px;
  padding: 18px 20px;
  align-self: flex-start;
}

.detail__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 14px;
}

.detail__title-box {
  min-width: 0;
}

.detail__title {
  margin: 6px 0 0;
  font-size: 18px;
  word-break: break-all;
}

.detail__ops {
  flex-shrink: 0;
  display: flex;
}

.detail__block {
  margin-bottom: 16px;
}

.block__label {
  font-size: 12px;
  color: var(--vb-text-2);
  margin-bottom: 6px;
}

.content-box {
  border: 1px solid var(--vb-border);
  border-radius: 8px;
  background: var(--vb-hover);
}

.content-box__toolbar {
  display: flex;
  justify-content: space-between;
  border-bottom: 1px dashed var(--vb-border);
  padding: 2px 6px;
}

.content-box__body {
  padding: 12px 14px;
  min-height: 56px;
  line-height: 1.7;
  font-size: 13.5px;
  overflow-wrap: anywhere;
}

.content-box__body.masked {
  letter-spacing: 2px;
}

.masked-text {
  color: var(--vb-text-2);
}

.muted {
  color: var(--vb-text-2);
}

.clip-hint {
  margin-top: 8px;
  font-size: 12px;
  color: var(--el-color-warning);
  display: flex;
  align-items: center;
}

.note-box {
  white-space: pre-wrap;
  line-height: 1.7;
  font-size: 13px;
  color: var(--vb-text-1);
}

.detail__meta {
  display: flex;
  gap: 16px;
  font-size: 11.5px;
  color: var(--vb-text-2);
  border-top: 1px solid var(--vb-border);
  padding-top: 12px;
}

/* ---------- 弹窗 ---------- */
.mask-row {
  margin: -10px 0 16px;
  font-size: 12px;
}

.conflict-tip {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 13px;
  margin-bottom: 14px;
}

.conflict-opts {
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
}

.conflict-opt {
  height: auto;
  width: 100%;
  margin-right: 0;
  padding: 10px 14px;
  white-space: normal;
}

.conflict-opt__title {
  font-weight: 600;
  font-size: 13.5px;
}

.conflict-opt__desc {
  font-size: 12px;
  color: var(--vb-text-2);
  margin-top: 2px;
}
</style>
