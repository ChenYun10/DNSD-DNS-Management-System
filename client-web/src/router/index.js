import { createRouter, createWebHistory } from 'vue-router'
import { session } from '../store/session'
import { auth } from '../api/auth'

const routes = [
  { path: '/login', name: 'login', component: () => import('../views/LoginView.vue') },
  {
    path: '/',
    component: () => import('../layout/AppLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/setup' },
      { path: 'setup', name: 'setup', component: () => import('../views/SetupView.vue') },
      { path: 'analytics', name: 'analytics', component: () => import('../views/AnalyticsView.vue') },
      { path: 'logs', name: 'logs', component: () => import('../views/LogsView.vue') },
      { path: 'settings', name: 'settings', component: () => import('../views/SettingsView.vue') },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to) => {
  if (to.meta.requiresAuth && !session.isAuthed()) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  // 整页刷新后 profile 内存丢失但 token 仍在：进入认证页面前先恢复
  if (to.meta.requiresAuth && session.isAuthed() && !session.user) {
    try {
      const me = await auth.me()
      session.setProfile(me.user, me.tenant || null)
    } catch {
      session.clear()
      return { name: 'login', query: { redirect: to.fullPath } }
    }
  }
  if (to.name === 'login' && session.isAuthed()) {
    return { path: '/' }
  }
  return true
})

export default router
