<template>
  <div class="flex min-h-screen items-center justify-center bg-bg px-4">
    <div class="w-full max-w-sm">
      <!-- 品牌 -->
      <div class="mb-8 text-center">
        <div class="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl text-2xl font-black" style="background: linear-gradient(135deg, #34d399, #22d3ee)">
          <span class="text-bg">D</span>
        </div>
        <h1 class="text-xl font-bold tracking-tight">DNSD 客户端门户</h1>
        <p class="mt-1 text-[13px] text-ink-dim">多租户 DNS · DoT / DoH / DoQ</p>
      </div>

      <!-- 登录表单 -->
      <form v-if="mode === 'login'" class="card space-y-4 p-6" @submit.prevent="onLogin">
        <div class="space-y-1.5">
          <label class="text-[12px] font-medium text-ink-dim">用户名</label>
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-[13px] outline-none transition-colors placeholder:text-ink-faint focus:border-accent"
            placeholder="admin"
            required
          />
        </div>
        <div class="space-y-1.5">
          <label class="text-[12px] font-medium text-ink-dim">密码</label>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-[13px] outline-none transition-colors placeholder:text-ink-faint focus:border-accent"
            placeholder="••••••••"
            required
          />
        </div>
        <button
          type="submit"
          :disabled="busy"
          class="w-full rounded-lg py-2.5 text-[14px] font-semibold text-bg transition-opacity disabled:opacity-50"
          style="background: linear-gradient(135deg, #34d399, #22d3ee)"
        >
          {{ busy ? '登录中…' : '登 录' }}
        </button>
        <div v-if="notice" class="rounded-lg border border-accent/30 bg-accent/10 px-3 py-2 text-[12.5px] text-accent">
          {{ notice }}
        </div>
        <div v-if="msg" class="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[12.5px] text-danger">
          {{ msg }}
        </div>
      </form>

      <!-- 强制改密表单 -->
      <form v-else class="card space-y-4 p-6" @submit.prevent="onChangePassword">
        <div class="text-center">
          <div class="text-2xl">🔒</div>
          <div class="mt-2 text-[14px] font-semibold">首次登录需修改密码</div>
          <p class="mt-1 text-[12px] text-ink-dim">至少 10 位，需包含大小写字母、数字与特殊字符</p>
        </div>
        <div class="space-y-1.5">
          <label class="text-[12px] font-medium text-ink-dim">当前密码</label>
          <input v-model="oldPassword" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-[13px] outline-none focus:border-accent" required />
        </div>
        <div class="space-y-1.5">
          <label class="text-[12px] font-medium text-ink-dim">新密码</label>
          <input v-model="newPassword" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-[13px] outline-none focus:border-accent" required />
        </div>
        <div class="space-y-1.5">
          <label class="text-[12px] font-medium text-ink-dim">确认新密码</label>
          <input v-model="confirmPassword" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2.5 text-[13px] outline-none focus:border-accent" required />
        </div>
        <button
          type="submit"
          :disabled="busy"
          class="w-full rounded-lg py-2.5 text-[14px] font-semibold text-bg transition-opacity disabled:opacity-50"
          style="background: linear-gradient(135deg, #34d399, #22d3ee)"
        >
          {{ busy ? '提交中…' : '修改并继续' }}
        </button>
        <div v-if="msg" class="rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[12.5px] text-danger">
          {{ msg }}
        </div>
      </form>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { session } from '../store/session'
import { auth } from '../api/auth'

const router = useRouter()
const route = useRoute()

const mode = ref('login')
const username = ref('')
const password = ref('')
const oldPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const busy = ref(false)
const msg = ref('')
const notice = ref('')

// 登录成功后的收尾：拉取 profile 并跳转
async function afterAuth() {
  const me = await auth.me()
  session.setProfile(me.user, me.tenant || null)
  router.push(route.query.redirect || '/')
}

async function onLogin() {
  busy.value = true
  msg.value = ''
  try {
    const res = await auth.login(username.value, password.value)
    // 强制改密流程：token 为受限 scope，只能改密
    if (res.must_change_password) {
      session.setTokens(res.access_token, '')
      mode.value = 'changePassword'
      oldPassword.value = password.value
      return
    }
    session.setTokens(res.access_token, res.refresh_token)
    await afterAuth()
  } catch (e) {
    msg.value = e.message || '登录失败'
  } finally {
    busy.value = false
  }
}

async function onChangePassword() {
  if (newPassword.value !== confirmPassword.value) {
    msg.value = '两次输入的新密码不一致'
    return
  }
  busy.value = true
  msg.value = ''
  try {
    await auth.changePassword(oldPassword.value, newPassword.value)
    // 改密成功：清空受限 token，回到登录表单重新登录
    session.clear()
    mode.value = 'login'
    newPassword.value = ''
    confirmPassword.value = ''
    oldPassword.value = ''
    password.value = ''
    msg.value = ''
    notice.value = '密码已修改，请使用新密码重新登录'
  } catch (e) {
    msg.value = e.message || '修改失败'
  } finally {
    busy.value = false
  }
}
</script>
