<script setup lang="ts">
/**
 * /setup/mode —— 模式选择页（§6.1）
 * 本地保险箱（离线单文件） / 联网保险箱（自建服务器同步），两张对比卡片
 */
import { useRouter } from 'vue-router'
import { FolderOpened, Connection } from '@element-plus/icons-vue'
import { useVaultStore } from '../stores/vault'
import { BRAND } from '../brand'
import logoUrl from '../assets/brand/logo.png'

const router = useRouter()
const store = useVaultStore()

/** 已确定过模式（回访本页）：可直接去解锁 */
function goUnlock() {
  if (store.mode) router.push('/unlock')
}

const LOCAL_FEATURES = ['数据保存在本机单个加密文件中', '完全离线，无需任何服务器', '文件可复制到其他设备解锁', '适合单机个人使用']
const REMOTE_FEATURES = ['多设备间自动同步', '冲突条目支持三选处理', '服务器端只保存密文，无法读取内容', '需要一台自建 VaultBox 服务器']
</script>

<template>
  <div class="vb-auth-page">
    <div class="page-inner">
      <div class="vb-brand">
        <img class="vb-brand__logo vb-brand__logo--img" :src="logoUrl" alt="VaultBox" />
        <div>
          <div class="vb-brand__name">Vault<em>Box</em></div>
          <div class="vb-brand__sub">端到端加密的私人保险箱 · {{ BRAND.studio }} 出品</div>
        </div>
      </div>

      <h2 class="page-title">选择保险箱模式</h2>
      <p class="page-desc">两种模式使用同一套端到端加密内核，仅数据存放方式不同。</p>

      <div class="mode-grid">
        <!-- 本地模式卡片 -->
        <div class="mode-card" tabindex="0" @click="router.push('/setup/local')" @keydown.enter="router.push('/setup/local')">
          <div class="mode-card__head">
            <div class="mode-card__icon local">
              <el-icon :size="20"><FolderOpened /></el-icon>
            </div>
            <div>
              <div class="mode-card__title">本地保险箱</div>
              <div class="mode-card__tag">离线 · 单文件</div>
            </div>
          </div>
          <ul class="mode-card__feats">
            <li v-for="f in LOCAL_FEATURES" :key="f">{{ f }}</li>
          </ul>
          <el-button type="primary" round class="mode-card__btn">创建本地保险箱</el-button>
        </div>

        <!-- 联网模式卡片（微软商店版为纯本地存储，不展示） -->
        <div v-if="store.edition !== 'store'" class="mode-card" tabindex="0" @click="router.push('/setup/remote')" @keydown.enter="router.push('/setup/remote')">
          <div class="mode-card__head">
            <div class="mode-card__icon remote">
              <el-icon :size="20"><Connection /></el-icon>
            </div>
            <div>
              <div class="mode-card__title">联网保险箱</div>
              <div class="mode-card__tag">多端同步 · 自建服务器</div>
            </div>
          </div>
          <ul class="mode-card__feats">
            <li v-for="f in REMOTE_FEATURES" :key="f">{{ f }}</li>
          </ul>
          <el-button type="primary" round class="mode-card__btn">连接并注册</el-button>
        </div>
      </div>

      <el-alert
        v-if="store.edition === 'store'"
        type="info"
        :closable="false"
        show-icon
        class="store-note"
        title="微软商店版"
        description="本版本仅提供本地存储，不包含联网同步功能。数据完全保存在你的设备上。"
      />

      <div v-if="store.mode" class="mode-foot">
        <span class="vb-text-link" @click="goUnlock">
          当前为{{ store.mode === 'local' ? '本地' : '联网' }}模式，直接去解锁 →
        </span>
      </div>

      <!-- 品牌页脚：官网宣传 -->
      <footer class="brand-foot">
        <span class="brand-foot__item">© {{ new Date().getFullYear() }} {{ BRAND.studio }}</span>
        <span class="brand-foot__dot">·</span>
        <span class="brand-foot__item">官方网站：{{ BRAND.websiteDisplay }}</span>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.page-inner {
  width: min(860px, 100%);
}

.page-title {
  font-size: 22px;
  margin: 0 0 6px;
}

.page-desc {
  color: var(--vb-text-2);
  margin: 0 0 24px;
  font-size: 13px;
}

.mode-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 18px;
}

.mode-card {
  background: var(--vb-card-bg);
  border: 1px solid var(--vb-border);
  border-radius: 14px;
  padding: 24px;
  cursor: pointer;
  transition:
    transform 0.18s ease,
    border-color 0.18s ease,
    box-shadow 0.18s ease;
  outline: none;
  display: flex;
  flex-direction: column;
}

.mode-card:hover,
.mode-card:focus-visible {
  transform: translateY(-3px);
  border-color: var(--vb-brand);
  box-shadow: 0 14px 34px -16px color-mix(in srgb, var(--vb-brand) 45%, transparent);
}

.mode-card__head {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 14px;
}

.mode-card__icon {
  width: 46px;
  height: 46px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
}

.mode-card__icon.local {
  background: linear-gradient(135deg, #6366f1, #8b5cf6);
}

.mode-card__icon.remote {
  background: linear-gradient(135deg, #0ea5e9, #6366f1);
}

.mode-card__title {
  font-size: 17px;
  font-weight: 600;
}

.mode-card__tag {
  font-size: 12px;
  color: var(--vb-text-2);
  margin-top: 2px;
}

.mode-card__feats {
  margin: 0 0 20px;
  padding: 0;
  list-style: none;
  flex: 1;
}

.mode-card__feats li {
  font-size: 13px;
  color: var(--vb-text-2);
  padding: 5px 0 5px 20px;
  position: relative;
}

.mode-card__feats li::before {
  content: '';
  position: absolute;
  left: 2px;
  top: 11px;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--vb-brand), var(--vb-brand-2));
}

.mode-card__btn {
  width: 100%;
}

.mode-foot {
  text-align: center;
  margin-top: 22px;
}

.store-note {
  margin-top: 18px;
}

.brand-foot {
  margin-top: 34px;
  text-align: center;
  font-size: 12px;
  color: var(--vb-text-2);
}

.brand-foot__dot {
  margin: 0 8px;
}

.vb-brand__logo--img {
  object-fit: cover;
  border-radius: 12px;
}
</style>
