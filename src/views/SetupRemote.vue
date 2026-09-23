<script setup lang="ts">
/**
 * /setup/remote —— 联网保险箱：服务器配置 + 注册（§6.1 / §6.2）
 * 表单：服务器地址/端口/HTTPS 开关 + [测试连接]（三态指示）+ 用户名/密码
 * 可选：保护问题（忘记密码恢复用，需服务器配合）
 * 注册成功 -> 自动登录进入主页；失败（如已注册）-> 转解锁页登录
 */
import { reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft, Connection } from '@element-plus/icons-vue'
import { useVaultStore, type RemoteForm } from '../stores/vault'
import {
  checkPasswordStrength,
  scorePassword,
  toVaultError,
} from '../composables/useVault'

const router = useRouter()
const store = useVaultStore()

interface RemoteFormData {
  address: string
  port: number
  https: boolean
  username: string
  password: string
  confirm: string
  question: string
  answer: string
}

// 服务器配置默认值：优先取已保存配置
const form = reactive<RemoteFormData>({
  address: store.serverCfg.address || '127.0.0.1',
  port: store.serverCfg.port || 3000,
  https: store.serverCfg.https,
  username: '',
  password: '',
  confirm: '',
  question: '',
  answer: '',
})

const formRef = ref<FormInstance>()
const submitting = ref(false)

/* ---------- 测试连接三态 ---------- */
type TestState =
  | { kind: 'idle' }
  | { kind: 'ok'; text: string }
  | { kind: 'err'; text: string }
const testState = ref<TestState>({ kind: 'idle' })
const testing = ref(false)

async function runTest() {
  if (testing.value) return
  testing.value = true
  testState.value = { kind: 'idle' }
  const started = performance.now()
  try {
    const res = await store.testRemote({
      address: form.address.trim(),
      port: form.port,
      https: form.https,
    })
    const ms = Math.max(1, Math.round(performance.now() - started))
    if (res.ok) {
      testState.value = {
        kind: 'ok',
        text: `连接正常 · 服务器版本 ${res.version ?? '未知'} · 延迟约 ${ms} ms`,
      }
      // 服务器可达即记住配置，方便下次解锁页预填
      store.setServerCfg({ address: form.address.trim(), port: form.port, https: form.https })
    } else {
      testState.value = { kind: 'err', text: res.error ?? '连接失败，请检查配置' }
    }
  } catch (e) {
    const ve = toVaultError(e)
    const tip =
      ve.code === 'unreachable'
        ? '无法连接服务器：请检查地址、端口与网络连通性'
        : ve.code === 'tls_error'
          ? '证书无效：请核对 HTTPS 开关，或使用受信任的证书'
          : ve.code === 'unauthorized' || ve.code === 'bad_request'
            ? '服务器返回异常：请确认服务器版本与协议'
            : ve.message
    testState.value = { kind: 'err', text: tip }
  } finally {
    testing.value = false
  }
}

/* ---------- 强度 ---------- */
const score = computed(() => scorePassword(form.password))
const scoreTexts = ['', '弱', '中', '强', '极强']
const scoreColors = ['', 'var(--el-color-danger)', 'var(--el-color-warning)', 'var(--el-color-success)', 'var(--el-color-success)']

/* ---------- 校验 ---------- */
const rules = reactive<FormRules<RemoteFormData>>({
  address: [
    { required: true, message: '请输入服务器地址（IP 或域名）', trigger: 'blur' },
    {
      validator: (_r, v: string, cb) => {
        if (!v.trim()) return cb()
        cb(/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v.trim()) ? undefined : new Error('地址格式不正确'))
      },
      trigger: 'blur',
    },
  ],
  port: [{ required: true, message: '请输入端口（1~65535）', trigger: 'blur' }],
  username: [
    {
      validator: (_r, v: string, cb) => {
        if (!v) cb(new Error('请输入用户名'))
        else if (!/^[A-Za-z0-9_.-]{3,64}$/.test(v)) cb(new Error('用户名需 3~64 位，仅限字母/数字/._-'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
  password: [
    {
      validator: (_r, v: string, cb) => {
        if (!v) cb(new Error('请设置登录密码'))
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
        if (!v) cb(new Error('请再次输入密码'))
        else if (v !== form.password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
  question: [
    {
      validator: (_r, v: string, cb) => {
        const both = !!v.trim() && !!form.answer.trim()
        const none = !v.trim() && !form.answer.trim()
        cb(both || none ? undefined : new Error('保护问题与答案需成对填写（或都留空）'))
      },
      trigger: 'blur',
    },
  ],
  answer: [
    {
      validator: (_r, v: string, cb) => {
        if (!form.question.trim() && !v.trim()) return cb()
        cb(v.trim().length >= 8 ? undefined : new Error('答案至少 8 个字符，建议用短语而非单词'))
      },
      trigger: 'blur',
    },
  ],
})

/** 注册提交：注册成功后尝试自动登录 */
async function submit() {
  if (submitting.value) return
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  submitting.value = true
  const payload: RemoteForm = {
    address: form.address.trim(),
    port: form.port,
    https: form.https,
    username: form.username.trim(),
    password: form.password,
    question: form.question.trim() || null,
    answer: form.answer.trim() || null,
  }
  const res = await store.registerRemote(payload)
  if (!res.ok) {
    submitting.value = false
    if (res.code === 'already_exists') {
      // 服务器上已注册 -> 引导去登录
      ElMessage.info('该账户已注册，请直接登录')
      router.push({ path: '/unlock', query: { username: payload.username } })
      return
    }
    ElMessage.error(res.message)
    return
  }
  // 注册成功：尝试自动登录进入主页
  const login = await store.loginRemote(payload)
  submitting.value = false
  if (login.ok) {
    ElMessage.success('注册成功，已进入保险箱')
    router.push('/vault')
  } else {
    ElMessage.success('注册成功，请登录')
    router.push({ path: '/unlock', query: { username: payload.username } })
  }
}

/** 已有账户 -> 直接去登录页（置为远程模式） */
function goLogin() {
  store.mode = 'remote'
  store.persistMode()
  router.push({ path: '/unlock', query: { username: form.username || undefined } })
}
</script>

<template>
  <div class="vb-auth-page">
    <div
      v-loading="store.busy || submitting"
      element-loading-text="正在注册账户…"
      element-loading-background="rgba(127, 127, 127, 0.4)"
      class="vb-auth-card wide"
    >
      <div class="back-row">
        <el-button text size="small" @click="router.push('/setup/mode')">
          <el-icon><ArrowLeft /></el-icon>&nbsp;返回
        </el-button>
        <span class="step-tip">步骤 2 / 2 · 联网初始化</span>
      </div>

      <div class="vb-brand">
        <div class="vb-brand__logo">
          <el-icon><Connection /></el-icon>
        </div>
        <div>
          <div class="vb-brand__name">Vault<em>Box</em></div>
          <div class="vb-brand__sub">端到端加密 · 服务器只存密文</div>
        </div>
      </div>

      <h2 class="vb-auth-title">连接服务器并注册</h2>
      <p class="vb-auth-desc">填入你的 VaultBox 服务器信息；注册前可先[测试连接]确认可达。</p>

      <el-form ref="formRef" :model="form" :rules="rules" label-position="top" size="large">
        <div class="server-grid">
          <el-form-item label="服务器地址" prop="address" class="grow">
            <el-input v-model="form.address" placeholder="IP 或域名，如 192.168.1.10" autocomplete="off" />
          </el-form-item>
          <el-form-item label="端口" prop="port" class="port">
            <el-input-number v-model="form.port" :min="1" :max="65535" :controls="false" style="width: 100%" />
          </el-form-item>
          <el-form-item label="HTTPS" class="https">
            <el-switch v-model="form.https" />
          </el-form-item>
        </div>

        <div class="test-row">
          <el-button :loading="testing" size="small" @click="runTest">测试连接</el-button>
          <!-- 三态指示：绿=正常 / 红=失败 -->
          <el-alert
            v-if="testState.kind === 'ok'"
            type="success"
            :closable="false"
            class="test-result"
            :title="testState.text"
            show-icon
          />
          <el-alert
            v-else-if="testState.kind === 'err'"
            type="error"
            :closable="false"
            class="test-result"
            :title="testState.text"
            show-icon
          />
        </div>

        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" placeholder="3~64 位，字母/数字/._-" autocomplete="off" />
        </el-form-item>

        <div class="two-col">
          <el-form-item label="登录密码" prop="password">
            <el-input
              v-model="form.password"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="至少 10 位"
            />
          </el-form-item>
          <el-form-item label="再次输入" prop="confirm">
            <el-input
              v-model="form.confirm"
              type="password"
              show-password
              autocomplete="new-password"
              placeholder="与上方一致"
            />
          </el-form-item>
        </div>

        <div v-if="form.password" class="strength">
          <div class="strength__bar">
            <div
              v-for="i in 4"
              :key="i"
              class="strength__seg"
              :style="{ background: i <= score ? scoreColors[score] : 'var(--vb-border)' }"
            />
          </div>
          <span class="strength__label" :style="{ color: score ? scoreColors[score] : '' }">
            {{ scoreTexts[score] || '密码强度' }}
          </span>
        </div>

        <!-- 保护问题（可选） -->
        <el-divider content-position="left" class="opt-divider">保护问题（可选，用于找回密码）</el-divider>
        <el-form-item prop="question">
          <el-input v-model="form.question" placeholder="例如：我小学班主任的名字？" autocomplete="off" />
        </el-form-item>
        <el-form-item v-if="form.question" prop="answer">
          <el-input
            v-model="form.answer"
            type="password"
            show-password
            autocomplete="off"
            placeholder="答案至少 8 个字符"
          />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" class="submit" :loading="store.busy || submitting" @click="submit">
            注册并进入保险箱
          </el-button>
        </el-form-item>
      </el-form>

      <div class="foot">
        <span class="vb-text-link" @click="goLogin">已有账户？直接登录 →</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.vb-auth-card.wide {
  width: min(560px, 100%);
}

.back-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin: -8px 0 10px;
}

.step-tip {
  font-size: 12px;
  color: var(--vb-text-2);
}

.server-grid {
  display: flex;
  gap: 12px;
  align-items: flex-start;
}

.server-grid .grow {
  flex: 1;
}

.server-grid .port {
  width: 110px;
  flex-shrink: 0;
}

.server-grid .https {
  width: 76px;
  flex-shrink: 0;
}

.test-row {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin: -4px 0 18px;
}

.test-result {
  flex: 1;
  min-width: 0;
}

.two-col {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}

.strength {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: -10px 0 16px;
}

.strength__bar {
  display: flex;
  gap: 4px;
  flex: 1;
}

.strength__seg {
  height: 4px;
  border-radius: 2px;
  flex: 1;
  transition: background 0.2s ease;
}

.strength__label {
  font-size: 12px;
  color: var(--vb-text-2);
  white-space: nowrap;
}

.opt-divider {
  margin: 4px 0 14px;
}

.submit {
  width: 100%;
  margin-top: 4px;
}

.foot {
  text-align: center;
  margin-top: 4px;
}
</style>
