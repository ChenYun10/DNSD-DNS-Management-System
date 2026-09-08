import { createRouter, createWebHistory } from 'vue-router'
import { session } from '../store/session'

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

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !session.isAuthed()) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (to.name === 'login' && session.isAuthed()) {
    return { path: '/' }
  }
  return true
})

export default router
