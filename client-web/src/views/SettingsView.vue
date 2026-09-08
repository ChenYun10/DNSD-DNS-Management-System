<template>
  <div class="mx-auto max-w-3xl space-y-6 p-4 md:p-6">
    <div>
      <h1 class="text-lg font-semibold">设置</h1>
      <p class="mt-0.5 text-[13px] text-ink-dim">租户协议开关、DoT 前缀定制与账号安全。</p>
    </div>

    <StateView :loading="loading" :empty="empty" />

    <template v-if="!loading && tenant">
      <!-- 租户信息 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">租户信息</h2>
        <dl class="mt-4 grid gap-x-6 gap-y-3 text-[13px] sm:grid-cols-2">
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">名称</dt><dd class="text-ink">{{ tenant.name || '—' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">基域</dt><dd class="mono text-ink">{{ tenant.base_domain || '—' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">DoT 前缀</dt><dd class="mono text-ink">{{ tenant.prefix || '未设置' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">VIP 通道</dt><dd class="text-ink">{{ tenant.vip ? '已启用' : '否' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">限流 QPS</dt><dd class="text-ink">{{ tenant.rate_limit_qps || '—' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">缓存 TTL 上限</dt><dd class="text-ink">{{ tenant.cache_max_ttl ? tenant.cache_max_ttl + 's' : '—' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">默认 ECS</dt><dd class="mono text-ink">{{ tenant.default_ecs || '—' }}</dd></div>
          <div class="flex justify-between gap-4 sm:block"><dt class="text-ink-faint">接受客户端 ECS</dt><dd class="text-ink">{{ tenant.allow_ecs ? '是' : '否' }}</dd></div>
        </dl>
      </div>

      <!-- 协议开关 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">接入协议</h2>
        <p class="mt-1 text-[12px] text-ink-dim">控制该租户可用的下行协议。</p>
        <div class="mt-4 space-y-3">
          <div v-for="p in protocols" :key="p.key" class="flex items-center justify-between rounded-lg border border-line-soft bg-surface-2 px-4 py-3">
            <div>
              <div class="text-[13.5px] font-medium">{{ p.name }}</div>
              <div class="text-[12px] text-ink-dim">{{ p.desc }}</div>
            </div>
            <Toggle :model-value="tenant[p.key]" :disabled="saving === p.key" @update:model-value="(v) => toggleProtocol(p.key, v)" />
          </div>
        </div>
      </div>

      <!-- DoT 前缀 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">DoT 前缀定制</h2>
        <p class="mt-1 text-[12px] text-ink-dim">3–32 位小写字母/数字/连字符。修改后 DoT/DoH 端点同步更新。</p>
        <form class="mt-4 flex gap-3" @submit.prevent="savePrefix">
          <input
            v-model="prefixInput"
            type="text"
            class="flex-1 rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent"
            :placeholder="tenant.prefix || '例如 acme-01'"
          />
          <button type="submit" :disabled="savingPrefix" class="rounded-lg px-4 py-2 text-[13px] font-semibold text-bg disabled:opacity-50" style="background: linear-gradient(135deg, #34d399, #22d3ee)">
            {{ savingPrefix ? '保存中…' : '保存前缀' }}
          </button>
        </form>
      </div>

      <!-- 改密码 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">修改密码</h2>
        <p class="mt-1 text-[12px] text-ink-dim">至少 10 位，需包含大小写字母、数字与特殊字符。</p>
        <form class="mt-4 space-y-3" @submit.prevent="savePassword">
          <div>
            <label class="mb-1 block text-[12px] text-ink-dim">当前密码</label>
            <input v-model="pwd.old" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" required />
          </div>
          <div>
            <label class="mb-1 block text-[12px] text-ink-dim">新密码</label>
            <input v-model="pwd.next" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" required />
          </div>
          <div>
            <label class="mb-1 block text-[12px] text-ink-dim">确认新密码</label>
            <input v-model="pwd.confirm" type="password" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" required />
          </div>
          <div class="flex items-center gap-3">
            <button type="submit" :disabled="savingPwd" class="rounded-lg border border-line px-4 py-2 text-[13px] font-medium text-ink transition-colors hover:bg-surface-2 disabled:opacity-50">
              {{ savingPwd ? '提交中…' : '修改密码' }}
            </button>
            <span v-if="pwdMsg" class="text-[12.5px]" :class="pwdOk ? 'text-accent' : 'text-danger'">{{ pwdMsg }}</span>
          </div>
        </form>
      </div>
    </template>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { session } from '../store/session'
import { api } from '../api/endpoints'
import { auth } from '../api/auth'
import Toggle from '../components/Toggle.vue'
import StateView from '../components/StateView.vue'

const router = useRouter()
const loading = ref(true)
const empty = ref('')
const tenant = ref(null)
const saving = ref('')
const savingPrefix = ref(false)
const prefixInput = ref('')

const protocols = [
  { key: 'dot_enabled', name: 'DoT（DNS over TLS）', desc: '端口 853，SNI 路由租户' },
  { key: 'doh_enabled', name: 'DoH（DNS over HTTPS）', desc: '端口 443，Host 路由租户' },
  { key: 'doq_enabled', name: 'DoQ（DNS over QUIC）', desc: '基于 QUIC 的加密解析' },
]

const pwd = reactive({ old: '', next: '', confirm: '' })
const savingPwd = ref(false)
const pwdMsg = ref('')
const pwdOk = ref(false)

async function load() {
  loading.value = true
  try {
    let id = session.tenantId()
    if (!id && session.user?.tenant_id) id = session.user.tenant_id
    if (!id) {
      empty.value = '当前账号未绑定租户'
      return
    }
    tenant.value = await api.tenant(id)
    session.tenant = tenant.value
    prefixInput.value = tenant.value.prefix || ''
  } catch (e) {
    empty.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
}

async function toggleProtocol(key, val) {
  saving.value = key
  try {
    const t = await api.customizeDot(tenant.value.id, { [key]: val })
    tenant.value = t
    session.tenant = t
  } catch (e) {
    // 回滚展示
    tenant.value[key] = !val
    alert(e.message || '操作失败')
  } finally {
    saving.value = ''
  }
}

async function savePrefix() {
  if (!prefixInput.value.trim()) return
  savingPrefix.value = true
  try {
    const t = await api.customizeDot(tenant.value.id, { prefix: prefixInput.value.trim() })
    tenant.value = t
    session.tenant = t
  } catch (e) {
    alert(e.message || '保存失败')
  } finally {
    savingPrefix.value = false
  }
}

async function savePassword() {
  if (pwd.next !== pwd.confirm) {
    pwdMsg.value = '两次输入的新密码不一致'
    pwdOk.value = false
    return
  }
  savingPwd.value = true
  pwdMsg.value = ''
  try {
    await auth.changePassword(pwd.old, pwd.next)
    pwdOk.value = true
    pwdMsg.value = '密码已修改，即将重新登录…'
    setTimeout(() => {
      session.clear()
      router.push('/login')
    }, 1200)
  } catch (e) {
    pwdOk.value = false
    pwdMsg.value = e.message || '修改失败'
  } finally {
    savingPwd.value = false
  }
}

onMounted(load)
</script>
