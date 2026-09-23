/**
 * 路由与守卫（CONTRACT §6 / 主文档 §7.2）
 * 路由：/setup/mode /setup/local /setup/remote /unlock /recover /vault /settings
 * 守卫规则：
 *   - 未解锁访问 /vault、/settings -> 弹回 /unlock
 *   - 已解锁访问 /setup/*、/unlock    -> 弹回 /vault
 *   - mode 未确定（从未初始化）时 /unlock -> /setup/mode
 */
import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'
import { useVaultStore } from '../stores/vault'

/** 需已解锁才能访问的页面 */
const LOCKED_PATHS = ['/vault', '/settings']
/** 登录/设置流程公开页（无需解锁，但受 mode 约束） */
const PUBLIC_PATHS = ['/setup/mode', '/setup/local', '/setup/remote', '/unlock', '/recover']

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/vault' },
  {
    path: '/setup/mode',
    name: 'setup-mode',
    component: () => import('../views/SetupMode.vue'),
  },
  {
    path: '/setup/local',
    name: 'setup-local',
    component: () => import('../views/SetupLocal.vue'),
  },
  {
    path: '/setup/remote',
    name: 'setup-remote',
    component: () => import('../views/SetupRemote.vue'),
  },
  {
    path: '/unlock',
    name: 'unlock',
    component: () => import('../views/Unlock.vue'),
  },
  {
    path: '/recover',
    name: 'recover',
    component: () => import('../views/Recover.vue'),
  },
  {
    path: '/vault',
    name: 'vault',
    component: () => import('../views/VaultHome.vue'),
  },
  {
    path: '/settings',
    name: 'settings',
    component: () => import('../views/Settings.vue'),
  },
  // 兜底：未知路径回到主页
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  // 桌面 WebView 下 hash 模式更稳妥（无需服务端 rewrite）
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const store = useVaultStore()

  // 微软商店版为纯本地存储：屏蔽联网初始化入口
  if (to.path === '/setup/remote' && store.edition === 'store') {
    return { path: '/setup/local' }
  }

  // 根路径按会话状态分流
  if (to.path === '/') {
    if (!store.mode) return { path: '/setup/mode' }
    return store.unlocked ? { path: '/vault' } : { path: '/unlock' }
  }

  if (PUBLIC_PATHS.includes(to.path)) {
    // 已解锁后不允许再进初始化/解锁流程
    if (store.unlocked && to.path.startsWith('/setup')) return { path: '/vault' }
    // 从未初始化过：解锁页也没有意义，去选模式
    if (to.path === '/unlock' && !store.mode) return { path: '/setup/mode' }
    return true
  }

  // /vault、/settings：必须已解锁
  if (LOCKED_PATHS.includes(to.path)) {
    if (!store.unlocked) {
      // 从未初始化过直接去选模式，否则去解锁
      return store.mode ? { path: '/unlock' } : { path: '/setup/mode' }
    }
  }
  return true
})

export default router
