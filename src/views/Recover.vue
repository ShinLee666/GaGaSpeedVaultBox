<script setup lang="ts">
/**
 * /recover —— 忘记密码：用保护问题答案重置（§6.5，本地模式）
 * 流程：输入答案 -> 校验通过后设置新密码（强度规则与 Rust 端一致）
 * 答案规范化（NFKC + trim + 小写）在 useVault 内完成
 */
import { reactive, ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { ArrowLeft, RefreshLeft } from '@element-plus/icons-vue'
import { useVaultStore } from '../stores/vault'
import { checkPasswordStrength, scorePassword } from '../composables/useVault'

const router = useRouter()
const store = useVaultStore()

const formRef = ref<FormInstance>()
const submitting = ref(false)

const form = reactive({
  answer: '',
  password: '',
  confirm: '',
})

/** 当前为远程模式：本页仅适用于本地保险箱文件 */
const isRemote = computed(() => store.mode === 'remote')

const score = computed(() => scorePassword(form.password))
const scoreTexts = ['', '弱', '中', '强', '极强']
const scoreColors = ['', 'var(--el-color-danger)', 'var(--el-color-warning)', 'var(--el-color-success)', 'var(--el-color-success)']

const rules = reactive<FormRules>({
  answer: [
    { required: true, message: '请输入保护问题答案', trigger: 'blur' },
    {
      validator: (_r, v: string, cb) =>
        cb(v.trim().length >= 1 ? undefined : new Error('请输入答案')),
      trigger: 'change',
    },
  ],
  password: [
    {
      validator: (_r, v: string, cb) => {
        if (!v) cb(new Error('请设置新密码'))
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
        else if (v !== form.password) cb(new Error('两次输入的密码不一致'))
        else cb()
      },
      trigger: 'blur',
    },
  ],
})

async function submit() {
  if (submitting.value || isRemote.value) return
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return
  submitting.value = true
  const res = await store.recover(form.answer, form.password)
  submitting.value = false
  if (res.ok) {
    ElMessage.success(res.message)
    // 重置成功后回到解锁页
    store.mode = 'local'
    store.persistMode()
    store.unlocked = false
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
      element-loading-text="正在重置密码…（安全计算较慢，请稍候）"
      element-loading-background="rgba(127, 127, 127, 0.4)"
      class="vb-auth-card"
    >
      <div class="back-row">
        <el-button text size="small" @click="router.push('/unlock')">
          <el-icon><ArrowLeft /></el-icon>&nbsp;返回解锁
        </el-button>
      </div>

      <div class="vb-brand">
        <div class="vb-brand__logo">
          <el-icon><RefreshLeft /></el-icon>
        </div>
        <div>
          <div class="vb-brand__name">Vault<em>Box</em></div>
          <div class="vb-brand__sub">保护问题重置密码</div>
        </div>
      </div>

      <h2 class="vb-auth-title">重置密码</h2>
      <p class="vb-auth-desc">
        输入当初设置的保护问题答案，验证通过后即可设置新密码。
        <strong>若答案也忘记了，数据将无法找回</strong>——这是端到端加密的必然结果。
      </p>

      <!-- 远程模式提示 -->
      <el-alert
        v-if="isRemote"
        type="warning"
        :closable="false"
        show-icon
        title="当前为联网模式"
        description="密码重置接口仅面向本地保险箱文件。联网模式忘记密码请联系服务器管理员处理。"
        class="remote-tip"
      />

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        size="large"
        :disabled="isRemote"
      >
        <el-form-item label="保护问题答案" prop="answer">
          <el-input
            v-model="form.answer"
            type="password"
            show-password
            autocomplete="off"
            placeholder="请输入答案（不区分大小写）"
          />
        </el-form-item>

        <el-form-item label="新密码" prop="password">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="至少 10 位，勿用常见口令"
          />
        </el-form-item>

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

        <el-form-item label="再次输入新密码" prop="confirm">
          <el-input
            v-model="form.confirm"
            type="password"
            show-password
            autocomplete="new-password"
            placeholder="与上方一致"
          />
        </el-form-item>

        <el-form-item>
          <el-button
            type="primary"
            class="submit"
            :loading="store.busy || submitting"
            :disabled="isRemote"
            @click="submit"
          >
            重置密码
          </el-button>
        </el-form-item>
      </el-form>
    </div>
  </div>
</template>

<style scoped>
.back-row {
  margin: -8px 0 10px;
}

.remote-tip {
  margin-bottom: 18px;
}

.strength {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: -8px 0 16px;
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

.submit {
  width: 100%;
  margin-top: 4px;
}
</style>
