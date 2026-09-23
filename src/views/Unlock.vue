<script setup lang="ts">
/**
 * /unlock —— 解锁页（§6.3）
 * - local 模式：密码框回车解锁
 * - remote 模式：服务器地址/端口/HTTPS + 用户名/密码 + [测试连接]，登录后全量拉取
 * 路由守卫保证 mode 非空（从未初始化时先去 /setup/mode）
 */
import { reactive, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowRight } from '@element-plus/icons-vue'
import { useVaultStore } from '../stores/vault'
import { toVaultError } from '../composables/useVault'
import logoUrl from '../assets/brand/logo.png'

const router = useRouter()
const route = useRoute()
const store = useVaultStore()

const formRef = ref<FormInstance>()
const submitting = ref(false)

/** local: 仅密码；remote: 服务器 + 账户 */
const form = reactive({
  password: '',
  address: store.serverCfg.address || '127.0.0.1',
  port: store.serverCfg.port || 3000,
  https: store.serverCfg.https,
  username: '',
})

onMounted(() => {
  // 注册完成后跳转过来时预填用户名
  const q = route.query.username
  if (typeof q === 'string' && q) form.username = q
})

const rules = reactive<FormRules>({
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 1, message: '请输入密码', trigger: 'change' },
  ],
  address: [{ required: true, message: '请输入服务器地址', trigger: 'blur' }],
  port: [{ required: true, message: '请输入端口', trigger: 'blur' }],
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
})

/* ---------- 解锁本地 ---------- */
async function unlockLocal() {
  if (submitting.value) return
  submitting.value = true
  const res = await store.unlockLocal(form.password)
  submitting.value = false
  if (res.ok) {
    ElMessage.success('解锁成功')
    router.push('/vault')
  } else {
    ElMessage.error(res.message)
  }
}

/* ---------- 登录远程 ---------- */
async function loginRemote() {
  if (submitting.value) return
  submitting.value = true
  const res = await store.loginRemote({
    address: form.address.trim(),
    port: form.port,
    https: form.https,
    username: form.username.trim(),
    password: form.password,
  })
  submitting.value = false
  if (res.ok) {
    ElMessage.success('登录成功，已同步')
    router.push('/vault')
  } else {
    ElMessage.error(res.message)
  }
}

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
    const res = await store.testRemote({ address: form.address.trim(), port: form.port, https: form.https })
    const ms = Math.max(1, Math.round(performance.now() - started))
    if (res.ok) {
      testState.value = {
        kind: 'ok',
        text: `连接正常 · 服务器版本 ${res.version ?? '未知'} · 延迟约 ${ms} ms`,
      }
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
          : ve.message
    testState.value = { kind: 'err', text: tip }
  } finally {
    testing.value = false
  }
}

/** 提交入口：按模式分发 */
function submit() {
  formRef.value?.validate().then(() => {
    if (store.mode === 'remote') loginRemote()
    else unlockLocal()
  })
}

/** 回车快捷解锁 */
function onEnter() {
  submit()
}
</script>

<template>
  <div class="vb-auth-page">
    <div
      v-loading="store.busy || submitting"
      element-loading-text="正在验证并解密数据…（安全计算较慢，请稍候）"
      element-loading-background="rgba(127, 127, 127, 0.4)"
      class="vb-auth-card"
    >
      <div class="vb-brand">
        <img class="vb-brand__logo vb-brand__logo--img" :src="logoUrl" alt="VaultBox" />
        <div>
          <div class="vb-brand__name">Vault<em>Box</em></div>
          <div class="vb-brand__sub">
            {{ store.mode === 'remote' ? '联网保险箱 · 服务器同步' : '本地保险箱 · 端到端加密' }}
          </div>
        </div>
      </div>

      <h2 class="vb-auth-title">解锁保险箱</h2>
      <p class="vb-auth-desc">输入密码解锁。密码仅在本机派生密钥，我们无法帮你找回。</p>

      <el-form ref="formRef" :model="form" :rules="rules" label-position="top" size="large">
        <!-- 远程模式：服务器配置 -->
        <template v-if="store.mode === 'remote'">
          <div class="server-grid">
            <el-form-item label="服务器地址" prop="address" class="grow">
              <el-input v-model="form.address" placeholder="IP 或域名" autocomplete="off" />
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
            <el-input v-model="form.username" placeholder="用户名" autocomplete="off" @keyup.enter="onEnter" />
          </el-form-item>
        </template>

        <el-form-item :label="store.mode === 'remote' ? '登录密码' : '保险箱密码'" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="请输入密码"
            @keyup.enter="onEnter"
          >
            <template #suffix>
              <el-icon v-if="form.password" class="enter-icon" @click="submit"><ArrowRight /></el-icon>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" class="submit" :loading="store.busy || submitting" @click="submit">
            {{ store.mode === 'remote' ? '登录并同步' : '解锁' }}
          </el-button>
        </el-form-item>
      </el-form>

      <div class="foot">
        <!-- 本地模式支持保护问题恢复 -->
        <span v-if="store.mode === 'local'" class="vb-text-link" @click="router.push('/recover')">
          忘记密码？用保护问题重置
        </span>
        <span v-else class="vb-text-link" @click="router.push('/setup/mode')">
          忘记密码请联系服务器管理员，或改用本地保险箱
        </span>
        <el-divider direction="vertical" />
        <span class="vb-text-link" @click="router.push('/setup/mode')">更换保险箱模式</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
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

.enter-icon {
  cursor: pointer;
  color: var(--vb-brand);
}

.submit {
  width: 100%;
  margin-top: 4px;
}

.foot {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 4px;
  margin-top: 6px;
  flex-wrap: wrap;
}
</style>
