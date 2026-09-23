import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Tauri 惯例配置：固定端口 1420、关闭 clearScreen
// 生产构建由 src-tauri 调用 `tauri build`，本配置负责前端 dev/build
export default defineConfig({
  plugins: [vue()],

  // 1. 防止 Vite 清空终端（Tauri 需要保留 Rust 编译日志）
  clearScreen: false,

  // 2. Tauri 期望固定端口，便于 WebView 加载
  server: {
    port: 1420,
    strictPort: true,
  },

  // 3. 打包目标对齐 Windows WebView2（Chromium 105+）
  build: {
    target: 'chrome105',
    minify: 'esbuild',
    sourcemap: false,
  },
})
