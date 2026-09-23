/**
 * VaultBox 桌面端入口
 * - 完整引入 Element Plus 与全部图标（按 CONTRACT §6）
 * - 引入全局样式（含 Element Plus 深色 css-vars，html.dark 生效）
 * - 挂载 Pinia 与 vue-router
 */
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import * as ElementPlusIconsVue from '@element-plus/icons-vue'
import zhCn from 'element-plus/es/locale/lang/zh-cn'

import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/theme.css'

import App from './App.vue'
import router from './router'

const app = createApp(App)

// Element Plus 完整引入 + 中文语言包
app.use(ElementPlus, { locale: zhCn })

// 全局注册全部图标（模板里可按名称直接使用）
for (const [name, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(name, component)
}

app.use(createPinia())
app.use(router)

// 再次确保主题类已按本地偏好设置（防 index.html 内联脚本被禁用等边缘情况）
try {
  if (localStorage.getItem('vaultbox:theme') === 'dark') {
    document.documentElement.classList.add('dark')
  }
} catch {
  /* 忽略 */
}

app.mount('#app')
