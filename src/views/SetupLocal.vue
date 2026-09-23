<script setup lang="ts">
/**
 * /setup/local —— 本地保险箱初始化（§6.2）
 * 字段：保险箱密码（强度校验）+ 可选保护问题/答案 + 再次确认
 * 成功后直接进入保险箱主页（Rust 端已开启会话并写盘 data/vault.vault）
 */
import { reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft } from '@element-plus/icons-vue'
import { useVaultStore } from '../stores/vault'
import { checkPasswordStrength, scorePassword } from '../composables/useVault'

const router = useRouter()
const store = useVaultStore()

const formRef = ref<FormInstance>()

interface LocalForm {
  password: string
  confirm: string
  question: string
  answer: string
}

const form = reactive<LocalForm>({ password: '', confirm: '', question: '', answer: '' })
const submitting = ref(false)

/** 强度评分（0~4）与文案 */
const score = computed(() => scorePassword(form.password))
const scoreTexts = ['', '弱', '中', '强', '极强']
const scoreColors = ['', 'var(--el-color-danger)', 'var(--el-color-warning)', 'var(--el-color-success)', 'var(--el-color-success)']

/** 密码实时提示（输入未满 10 位时提示进度） */
const passwordHint = computed(() => {
  if (!form.password) return ''
  const c = checkPasswordStrength(form.password)
  if (c.ok) return ''
  return c.reason
})

/** 校验规则 */
const rules = reactive<FormRules<LocalForm>>({
  password: [
    {
      validator: (_rule, value: string, callback) => {
        const c = checkPasswordStrength(value)
        if (!value) callback(new Error('请设置保险箱密码'))
        else if (!c.ok) callback(new Error(c.reason))
        else callback()
      },
      trigger: 'blur',
    },
  ],
  confirm: [
    {
      validator: (_rule, value: string, callback) => {
        if (!value) callback(new Error('请再次输入密码'))
        else if (value !== form.password) callback(new Error('两次输入的密码不一致'))
        else callback()
      },
      trigger: 'blur',
    },
  ],
  question: [
    {
      validator: (_rule, value: string, callback) => {
        const both = value.trim() && form.answer.trim()
        const none = !value.trim() && !form.answer.trim()
        if (!both && !none) callback(new Error('保护问题与答案需成对填写（或都留空）'))
        else callback()
      },
      trigger: 'blur',
    },
  ],
  answer: [
    {
      validator: (_rule, value: string, callback) => {
        if (!form.question.trim() && !value.trim()) return callback()
        if (value.trim().length < 8) callback(new Error('答案至少 8 个字符，建议用短语而非单词'))
        else if (value === form.password) callback(new Error('答案不能与密码相同'))
        else callback()
      },
      trigger: 'blur',
    },
  ],
})

async function submit() {
  if (submitting.value) return
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  submitting.value = true
  const res = await store.initLocal(form.password, form.question.trim() || null, form.answer.trim() || null)
  submitting.value = false
  if (res.ok) {
    ElMessage.success('保险箱已创建，欢迎使用')
    router.push('/vault')
  } else if (res.code === 'already_exists') {
    // 该位置已存在保险箱 -> 直接引导解锁
    ElMessage.warning(res.message + '，请直接解锁')
    store.mode = 'local'
    store.persistMode()
    router.replace('/unlock')
  } else {
    ElMessage.error(res.message)
  }
}
</script>

<template>
  <div class="vb-auth-page">
    <div
      v-loading="store.busy || submitting"
      element-loading-text="正在生成密钥并创建保险箱…（Argon2id 计算较慢，请稍候）"
      element-loading-background="rgba(127, 127, 127, 0.4)"
      class="vb-auth-card"
    >
      <div class="back-row">
        <el-button text size="small" @click="router.push('/setup/mode')">
          <el-icon><ArrowLeft /></el-icon>&nbsp;返回
        </el-button>
        <span class="step-tip">步骤 2 / 2 · 本地初始化</span>
      </div>

      <div class="vb-brand">
        <div class="vb-brand__logo">
          <el-icon><Lock /></el-icon>
        </div>
        <div>
          <div class="vb-brand__name">Vault<em>Box</em></div>
          <div class="vb-brand__sub">端到端加密 · 数据不出本机</div>
        </div>
      </div>

      <h2 class="vb-auth-title">创建本地保险箱</h2>
      <p class="vb-auth-desc">
        将生成加密文件 <span class="vb-mono">data/vault.vault</span> 于应用数据目录。
        密码只在本机派生密钥，任何人也无法找回——请务必牢记。
      </p>

      <el-form ref="formRef" :model="form" :rules="rules" label-position="top" size="large">
        <el-form-item label="保险箱密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="off"
            placeholder="至少 10 位，包含字母与数字更佳"
          />
        </el-form-item>

        <!-- 强度计 -->
        <div v-if="form.password" class="strength">
          <div class="strength__bar">
            <div
              v-for="i in 4"
              :key="i"
              class="strength__seg"
              :style="{
                background: i <= score ? scoreColors[score] : 'var(--vb-border)',
              }"
            />
          </div>
          <span class="strength__label" :style="{ color: score ? scoreColors[score] : '' }">
            {{ scoreTexts[score] || '密码强度' }}
          </span>
          <span v-if="passwordHint" class="strength__hint">{{ passwordHint }}</span>
        </div>

        <el-form-item label="再次输入密码" prop="confirm">
          <el-input
            v-model="form.confirm"
            type="password"
            show-password
            autocomplete="off"
            placeholder="与上方密码一致"
          />
        </el-form-item>

        <el-form-item label="保护问题（可选，强烈推荐——忘记密码时用它恢复）" prop="question">
          <el-input v-model="form.question" placeholder="例如：我小学班主任的名字？" autocomplete="off" />
        </el-form-item>

        <el-form-item v-if="form.question" label="保护问题答案" prop="answer">
          <el-input
            v-model="form.answer"
            type="password"
            show-password
            autocomplete="off"
            placeholder="至少 8 个字符，建议用短语"
          />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" class="submit" :loading="store.busy || submitting" @click="submit">
            创建并进入保险箱
          </el-button>
        </el-form-item>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
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

.strength {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: -8px 0 16px;
  font-size: 12px;
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
  color: var(--vb-text-2);
  white-space: nowrap;
}

.strength__hint {
  color: var(--vb-text-2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 40%;
}

.submit {
  width: 100%;
  margin-top: 4px;
}
</style>
