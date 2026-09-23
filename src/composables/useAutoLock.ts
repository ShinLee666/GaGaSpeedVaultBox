/**
 * useAutoLock —— 空闲自动锁定（主文档 §6.3：默认 5 分钟可配）
 * - 监听键盘/鼠标/滚轮/触摸等任意活动，重置空闲计时
 * - 空闲达 store.autoLockMinutes（0 = 从不）后自动 lock 并跳回解锁页
 * - 调用方挂载在需要保护的主界面（VaultHome / Settings）即可
 */
import { onBeforeUnmount, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useVaultStore } from '../stores/vault'

/** 视为"用户活动"的事件（passive 监听不阻塞渲染） */
const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'touchstart', 'scroll']

export function useAutoLock() {
  const store = useVaultStore()
  const router = useRouter()

  let timer: number | undefined
  let locked = false

  /** 取消当前计时（组件卸载 / 重新计时前调用） */
  function clearTimer() {
    if (timer !== undefined) {
      window.clearTimeout(timer)
      timer = undefined
    }
  }

  /** 按当前配置的空闲时长排定自动锁定 */
  function schedule() {
    clearTimer()
    // 已锁定或配置为"从不"时不再计时
    if (!store.unlocked || store.autoLockMinutes <= 0) return
    timer = window.setTimeout(doAutoLock, store.autoLockMinutes * 60_000)
  }

  /** 任意用户活动：重置计时 */
  function poke() {
    if (locked || !store.unlocked) return
    schedule()
  }

  /** 触发自动锁定 */
  async function doAutoLock() {
    if (locked) return
    // 正在执行长运算（解锁 KDF / 同步等）时顺延，避免打断关键写操作
    if (store.busy) {
      schedule()
      return
    }
    locked = true
    await store.lock()
    locked = false
    ElMessage({ type: 'info', message: '长时间未操作，已自动锁定', duration: 2500 })
    if (router.currentRoute.value.path !== '/unlock') {
      router.push('/unlock')
    }
  }

  /** 供外部手动触发一次锁定（如设置页的"立即锁定"按钮） */
  async function lockNow() {
    clearTimer()
    await doAutoLock()
  }

  onMounted(() => {
    for (const evt of ACTIVITY_EVENTS) {
      window.addEventListener(evt, poke, { passive: true })
    }
    schedule()
  })

  onBeforeUnmount(() => {
    clearTimer()
    for (const evt of ACTIVITY_EVENTS) {
      window.removeEventListener(evt, poke)
    }
  })

  // 用户在设置页修改自动锁定时长后立即按新时长重新计时
  watch(
    () => store.autoLockMinutes,
    () => {
      if (store.unlocked) schedule()
    },
  )

  return { lockNow }
}
