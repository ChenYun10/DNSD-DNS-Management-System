<template>
  <div class="flex h-screen overflow-hidden bg-bg text-ink">
    <!-- 侧边栏 -->
    <aside
      class="flex w-60 shrink-0 flex-col border-r border-line bg-surface"
      :class="collapsed ? '-ml-60' : 'ml-0'"
      style="transition: margin 0.2s ease"
    >
      <!-- 品牌 -->
      <div class="flex items-center gap-3 px-5 py-5">
        <div
          class="flex h-9 w-9 items-center justify-center rounded-xl text-lg font-black"
          style="background: linear-gradient(135deg, #34d399, #22d3ee)"
        >
          <span class="text-bg">D</span>
        </div>
        <div class="leading-tight">
          <div class="text-[15px] font-bold tracking-tight">DNSD</div>
          <div class="text-[11px] text-ink-dim">客户端门户</div>
        </div>
      </div>

      <!-- 导航 -->
      <nav class="mt-2 flex flex-1 flex-col gap-1 px-3">
        <router-link
          v-for="item in nav"
          :key="item.to"
          :to="item.to"
          class="group flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13.5px] font-medium text-ink-dim transition-colors hover:bg-surface-2 hover:text-ink"
          :class="route.path.startsWith(item.to) ? 'bg-surface-2 text-ink' : ''"
        >
          <span class="flex h-5 w-5 items-center justify-center" v-html="item.icon"></span>
          <span>{{ item.label }}</span>
          <span
            v-if="route.path.startsWith(item.to)"
            class="ml-auto h-1.5 w-1.5 rounded-full bg-accent"
          ></span>
        </router-link>
      </nav>

      <!-- 用户卡 -->
      <div class="border-t border-line p-3">
        <div class="flex items-center gap-3 rounded-lg px-2 py-2">
          <div
            class="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-sm font-semibold"
            style="background: var(--color-surface-3); color: var(--color-accent)"
          >
            {{ initial }}
          </div>
          <div class="min-w-0 flex-1 leading-tight">
            <div class="truncate text-[13px] font-medium">{{ session.user?.username || '—' }}</div>
            <div class="truncate text-[11px] text-ink-dim">
              {{ tenantLabel }}
            </div>
          </div>
          <button
            class="text-ink-faint transition-colors hover:text-danger"
            title="退出登录"
            @click="onLogout"
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
          </button>
        </div>
      </div>
    </aside>

    <!-- 遮罩（移动端） -->
    <div
      v-if="!collapsed"
      class="fixed inset-0 z-20 bg-black/50 md:hidden"
      @click="collapsed = true"
    ></div>

    <!-- 主内容 -->
    <div class="flex min-w-0 flex-1 flex-col">
      <header class="flex h-14 shrink-0 items-center gap-3 border-b border-line px-4 md:px-6">
        <button
          class="rounded-lg p-1.5 text-ink-dim hover:bg-surface-2 md:hidden"
          @click="collapsed = !collapsed"
        >
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
            <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
          </svg>
        </button>
        <div class="text-[15px] font-semibold">{{ routeTitle }}</div>
        <div class="ml-auto flex items-center gap-2 text-[12px] text-ink-dim">
          <span
            v-if="session.tenant?.vip"
            class="rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-accent"
          >
            VIP
          </span>
          <span class="hidden sm:inline">{{ session.tenant?.prefix ? session.tenant.prefix + '.' + session.tenant.base_domain : '' }}</span>
        </div>
      </header>

      <main class="flex-1 overflow-y-auto">
        <router-view />
      </main>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { session } from '../store/session'
import { auth } from '../api/auth'

const route = useRoute()
const router = useRouter()
const collapsed = ref(true)

const nav = [
  {
    to: '/setup',
    label: '配置',
    icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>',
  },
  {
    to: '/analytics',
    label: '分析',
    icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
  },
  {
    to: '/logs',
    label: '日志',
    icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>',
  },
  {
    to: '/settings',
    label: '设置',
    icon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
  },
]

const routeTitle = computed(() => {
  const m = nav.find((n) => route.path.startsWith(n.to))
  return m ? m.label : 'DNSD'
})

const initial = computed(() => (session.user?.username || '?').charAt(0).toUpperCase())
const tenantLabel = computed(() => {
  if (session.tenant?.name) return session.tenant.name
  return session.user?.role || '—'
})

async function onLogout() {
  try {
    await auth.logout()
  } catch {
    /* ignore */
  }
  session.clear()
  router.push('/login')
}

onMounted(async () => {
  collapsed.value = window.innerWidth >= 768
  // 整页刷新后 user/tenant 内存丢失但 token 仍在：自动恢复 profile
  if (session.isAuthed() && !session.user) {
    try {
      const me = await auth.me()
      session.setProfile(me.user, me.tenant || null)
    } catch {
      session.clear()
      router.push('/login')
    }
  }
})
</script>
