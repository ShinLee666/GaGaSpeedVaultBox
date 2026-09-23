<script setup lang="ts">
/**
 * 应用根组件：提供 Element Plus 中文语言包 + 挂载路由视图
 */
import { onMounted } from 'vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import { useVaultStore } from './stores/vault'

const store = useVaultStore()

// 挂载后按持久化偏好应用主题（html.dark 类），并读取发行版形态（full/store）
onMounted(() => {
  store.applyTheme()
  store.loadAppInfo()
})
</script>

<template>
  <el-config-provider :locale="zhCn">
    <router-view v-slot="{ Component }">
      <transition name="vb-page-fade" mode="out-in">
        <component :is="Component" />
      </transition>
    </router-view>
  </el-config-provider>
</template>
