/// <reference types="vite/client" />

// 兼容 element-plus 未随包导出完整类型声明的 locale 路径（内容由官方 zh-cn 语言包提供）
declare module 'element-plus/es/locale/lang/zh-cn' {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const locale: any
  export default locale
}
