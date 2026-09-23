<script setup lang="ts">
/**
 * /settings —— 设置页
 * 外观（浅/深主题，localStorage 持久化 + html.dark）、自动锁定时长、
 * 修改密码（change_password）、关于（app_info）
 */
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft, Moon, Sunny, Lock, InfoFilled } from '@element-plus/icons-vue'
import { useVaultStore } from '../stores/vault'
import { useAutoLock } from '../composables/useAutoLock'
import { appInfo, checkPasswordStrength, scorePassword } from '../composables/useVault'
import { BRAND } from '../brand'
import logoUrl from '../assets/brand/logo.png'
import wechatQrUrl from '../assets/brand/wechat-qrcode.png'

const router = useRouter()
const store = useVaultStore()
// 设置页同样受空闲自动锁定保护
const { lockNow } = useAutoLock()

/* ---------- 主题 ---------- */
function changeTheme(v: string | number | boolean | undefined) {
  store.setTheme(v === 'dark' ? 'dark' : 'light')
}

/* ---------- 自动锁定 ---------- */
const lockOptions = [
  { value: 1, label: '1 分钟' },
  { value: 3, label: '3 分钟' },
  { value: 5, label: '5 分钟（默认）' },
  { value: 10, label: '10 分钟' },
  { value: 30, label: '30 分钟' },
  { value: 0, label: '从不（不推荐）' },
]

function changeAutoLock(v: string | number | boolean | undefined) {
  store.setAutoLockMinutes(Number(v ?? 5))
}

/* ---------- 修改密码 ---------- */
const pwdVisible = ref(false)
const pwdSubmitting = ref(false)
const pwdFormRef = ref<FormInstance>()
const pwdForm = reactive({ current: '', next: '', confirm: '' })

const pwdScore = computed(() => scorePassword(pwdForm.next))
const scoreTexts = ['', '弱', '中', '强', '极强']
const scoreColors = ['', 'var(--el-color-danger)', 'var(--el-color-warning)', 'var(--el-color-success)', 'var(--el-color-success)']

const pwdRules = reactive<FormRules>({
  current: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
  next: [
    {
      validator: (_r, v: string, cb) => {
        if (!v) cb(new Error('请输入新密码'))
        else {
          const c = checkPasswordStrength(v)
          cb(c.ok ? undefined : new Error(c.reason))
        }
      },
      trigger: 'blur',
    },
  ],
  confirm: [
    {
      validator: (_r, v: string, cb) => {
        if (!v) cb(new Error('请再次输入新密码'))
        else if (v !== pwdForm.next) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
})

function openPwd() {
  pwdForm.current = ''
  pwdForm.next = ''
  pwdForm.confirm = ''
  pwdVisible.value = true
}

async function submitPwd() {
  const valid = await pwdFormRef.value?.validate().catch(() => false)
  if (!valid || pwdSubmitting.value) return
  pwdSubmitting.value = true
  const res = await store.changePassword(pwdForm.current, pwdForm.next)
  pwdSubmitting.value = false
  if (res.ok) {
    ElMessage.success('密码已修改')
    pwdVisible.value = false
  } else {
    ElMessage.error(res.message)
  }
}

/* ---------- 关于 ---------- */
const info = reactive({ version: '—', edition: 'full' })

onMounted(async () => {
  try {
    const a = await appInfo()
    info.version = a.version ?? '—'
    info.edition = a.edition === 'store' ? 'store' : 'full'
  } catch {
    info.version = '0.1.0'
  }
})

/** 用系统默认浏览器打开官网（Tauri shell 插件；失败时退回复制链接） */
async function openWebsite() {
  try {
    const { open } = await import('@tauri-apps/plugin-shell')
    await open(BRAND.websiteUrl)
  } catch {
    ElMessage.info(`请手动访问 ${BRAND.websiteDisplay}`)
  }
}

/* ---------- 立即锁定 ---------- */
async function lockImmediately() {
  await lockNow()
}
</script>

<template>
  <div class="settings">
    <!-- 顶栏 -->
    <header class="topbar">
      <el-button text @click="router.push('/vault')">
        <el-icon><ArrowLeft /></el-icon>&nbsp;返回保险箱
      </el-button>
      <span class="topbar__title">设置</span>
      <span class="topbar__spacer" />
    </header>

    <div class="page">
      <!-- 外观 -->
      <section class="card">
        <h3 class="card__title">外观</h3>
        <div class="card__row">
          <div class="card__desc">
            <div class="card__label">主题</div>
            <div class="card__hint">深色模式更护眼，适合夜间使用</div>
          </div>
          <el-radio-group :model-value="store.theme" @update:model-value="changeTheme">
            <el-radio-button value="light">
              <el-icon style="margin-right: 4px; vertical-align: -2px"><Sunny /></el-icon>浅色
            </el-radio-button>
            <el-radio-button value="dark">
              <el-icon style="margin-right: 4px; vertical-align: -2px"><Moon /></el-icon>深色
            </el-radio-button>
          </el-radio-group>
        </div>
      </section>

      <!-- 自动锁定 -->
      <section class="card">
        <h3 class="card__title">安全</h3>
        <div class="card__row">
          <div class="card__desc">
            <div class="card__label">空闲自动锁定</div>
            <div class="card__hint">无操作达到设定时长后自动锁定保险箱并清空剪贴板</div>
          </div>
          <el-select
            :model-value="store.autoLockMinutes"
            style="width: 180px"
            @update:model-value="changeAutoLock"
          >
            <el-option v-for="o in lockOptions" :key="o.value" :value="o.value" :label="o.label" />
          </el-select>
        </div>

        <el-divider />

        <div class="card__row">
          <div class="card__desc">
            <div class="card__label">修改密码</div>
            <div class="card__hint">换用新口令重新包裹密钥，数据无需重新加密</div>
          </div>
          <el-button type="primary" plain @click="openPwd">修改密码</el-button>
        </div>
      </section>

      <!-- 保险箱信息 -->
      <section class="card">
        <h3 class="card__title">保险箱</h3>
        <div class="card__row">
          <div class="card__desc">
            <div class="card__label">当前模式</div>
            <div class="card__hint">
              {{
                store.mode === 'remote'
                  ? `联网同步 · ${store.serverCfg.https ? 'https' : 'http'}://${store.serverCfg.address}:${store.serverCfg.port}`
                  : '本地单文件 · data/vault.vault'
              }}
            </div>
          </div>
          <el-tag :type="store.mode === 'remote' ? 'primary' : 'success'" round effect="light">
            {{ store.mode === 'remote' ? '联网模式' : '本地模式' }}
          </el-tag>
        </div>
        <el-divider />
        <div class="card__row">
          <div class="card__desc">
            <div class="card__label">立即锁定</div>
            <div class="card__hint">清空内存明文与剪贴板，返回解锁页</div>
          </div>
          <el-button type="danger" plain @click="lockImmediately">
            <el-icon style="margin-right: 4px"><Lock /></el-icon>立即锁定
          </el-button>
        </div>
      </section>

      <!-- 关于 -->
      <section class="card">
        <h3 class="card__title">关于</h3>
        <div class="about">
          <img class="about__logo about__logo--img" :src="logoUrl" alt="VaultBox logo" />
          <div>
            <div class="about__name">
              VaultBox <span class="about__ver">v{{ info.version }}{{ info.edition === 'store' ? '（微软商店版·纯本地存储）' : '' }}</span>
            </div>
            <div class="about__desc">
              {{ BRAND.studio }} 出品的端到端加密私人保险箱。密码与密钥只在本机派生与使用，
              数据以 AES-256-GCM 加密，任何人（包括我们）都无法读取明文。
            </div>
            <div class="about__links">
              <el-link type="primary" :underline="false" @click="openWebsite">
                官方网站：{{ BRAND.websiteDisplay }}
              </el-link>
            </div>
          </div>
          <div class="about__qr">
            <img :src="wechatQrUrl" alt="微信公众号二维码" />
            <div class="about__qr-tip">{{ BRAND.wechatTip }}</div>
          </div>
        </div>
        <el-alert
          type="info"
          :closable="false"
          show-icon
          title="安全提示"
          description="保险箱密码无法找回：请妥善保管密码与保护问题答案，并定期将本地保险箱文件备份到安全位置。"
          class="about__tip"
        />
      </section>
    </div>

    <!-- 修改密码弹窗 -->
    <el-dialog v-model="pwdVisible" title="修改密码" width="min(440px, 92vw)" :close-on-click-modal="false">
      <el-form ref="pwdFormRef" :model="pwdForm" :rules="pwdRules" label-position="top" size="large">
        <el-form-item label="当前密码" prop="current">
          <el-input v-model="pwdForm.current" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新密码" prop="next">
          <el-input v-model="pwdForm.next" type="password" show-password autocomplete="new-password" placeholder="至少 10 位，勿用常见口令" />
        </el-form-item>
        <div v-if="pwdForm.next" class="pwd-strength">
          <div class="pwd-strength__bar">
            <div
              v-for="i in 4"
              :key="i"
              class="pwd-strength__seg"
              :style="{ background: i <= pwdScore ? scoreColors[pwdScore] : 'var(--vb-border)' }"
            />
          </div>
          <span :style="{ color: pwdScore ? scoreColors[pwdScore] : '' }">{{ scoreTexts[pwdScore] || '强度' }}</span>
        </div>
        <el-form-item label="再次输入新密码" prop="confirm">
          <el-input v-model="pwdForm.confirm" type="password" show-password autocomplete="new-password" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwdSubmitting" @click="submitPwd">确认修改</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.settings {
  min-height: 100vh;
  background: var(--vb-page-bg);
}

.topbar {
  height: 54px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 14px;
  background: var(--vb-card-bg);
  border-bottom: 1px solid var(--vb-border);
}

.topbar__title {
  font-weight: 600;
  font-size: 15px;
}

.topbar__spacer {
  flex: 1;
}

.page {
  width: min(680px, 100%);
  margin: 0 auto;
  padding: 22px 16px 40px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.card {
  background: var(--vb-card-bg);
  border: 1px solid var(--vb-border);
  border-radius: 12px;
  padding: 18px 20px;
}

.card__title {
  margin: 0 0 14px;
  font-size: 13px;
  font-weight: 600;
  color: var(--vb-text-2);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.card__row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.card__desc {
  min-width: 0;
}

.card__label {
  font-size: 14px;
  font-weight: 500;
}

.card__hint {
  font-size: 12px;
  color: var(--vb-text-2);
  margin-top: 3px;
}

.about {
  display: flex;
  gap: 14px;
  align-items: flex-start;
}

.about__logo {
  width: 46px;
  height: 46px;
  flex-shrink: 0;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  background: linear-gradient(135deg, var(--vb-brand), var(--vb-brand-2));
}

.about__logo--img {
  object-fit: cover;
}

.about__links {
  margin-top: 8px;
}

.about__qr {
  margin-left: auto;
  flex-shrink: 0;
  width: 108px;
  text-align: center;
}

.about__qr img {
  width: 96px;
  height: 96px;
  border-radius: 8px;
  border: 1px solid var(--vb-border);
  background: #fff;
  padding: 4px;
}

.about__qr-tip {
  font-size: 11px;
  color: var(--vb-text-2);
  line-height: 1.5;
  margin-top: 6px;
}

.about__name {
  font-size: 16px;
  font-weight: 700;
}

.about__ver {
  font-size: 12px;
  font-weight: 400;
  color: var(--vb-text-2);
}

.about__desc {
  font-size: 12.5px;
  color: var(--vb-text-2);
  line-height: 1.7;
  margin-top: 6px;
}

.about__tip {
  margin-top: 16px;
}

.pwd-strength {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: -12px 0 16px;
  font-size: 12px;
  color: var(--vb-text-2);
}

.pwd-strength__bar {
  display: flex;
  gap: 4px;
  flex: 1;
}

.pwd-strength__seg {
  height: 4px;
  border-radius: 2px;
  flex: 1;
  transition: background 0.2s ease;
}

:deep(.el-radio-button__inner) {
  padding-inline: 18px;
}
</style>
