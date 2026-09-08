<template>
  <div class="mx-auto max-w-5xl space-y-6 p-4 md:p-6">
    <!-- 页面头 -->
    <div>
      <h1 class="text-lg font-semibold">配置</h1>
      <p class="mt-0.5 text-[13px] text-ink-dim">将这些端点配置到你的设备、路由器或浏览器，即可使用私有 DNS。</p>
    </div>

    <StateView :loading="loading" :empty="empty" />

    <template v-if="!loading && endpoints">
      <!-- 端点卡片 -->
      <div class="grid gap-4 md:grid-cols-3">
        <div v-for="ep in endpointCards" :key="ep.name" class="card p-4">
          <div class="flex items-center gap-2">
            <span class="rounded-md px-1.5 py-0.5 text-[10.5px] font-bold tracking-wide" :style="{ background: 'var(--color-surface-3)', color: 'var(--color-accent)' }">
              {{ ep.name }}
            </span>
            <span class="text-[11px] text-ink-faint">端口 {{ ep.port }}</span>
          </div>
          <div class="mt-2 text-[12px] leading-relaxed text-ink-dim">{{ ep.desc }}</div>
          <div class="mt-3">
            <CopyField :value="ep.value" />
          </div>
        </div>
      </div>

      <!-- 客户端配置 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">设备配置</h2>
        <div class="mt-4 space-y-5">
          <div v-for="c in clientGuides" :key="c.title" class="rounded-lg border border-line-soft bg-surface-2 p-4">
            <div class="mb-2 flex items-center gap-2">
              <span class="text-[13px] font-medium">{{ c.title }}</span>
            </div>
            <p class="mb-2 text-[12px] text-ink-dim">{{ c.desc }}</p>
            <CopyField :value="c.value" />
          </div>
        </div>
      </div>

      <!-- 反向代理片段 -->
      <div class="card p-5">
        <h2 class="text-[14px] font-semibold">反向代理片段</h2>
        <p class="mt-1 text-[12px] text-ink-dim">用于将公网 443 流量转发到数据面 DoH 端口（dnsd :8443）。</p>
        <div class="mt-4 grid gap-4 lg:grid-cols-2">
          <div>
            <div class="mb-2 text-[12px] font-medium text-ink-dim">nginx</div>
            <pre class="mono overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 text-[11.5px] leading-relaxed text-ink">{{ endpoints.nginx_snippet }}</pre>
          </div>
          <div>
            <div class="mb-2 text-[12px] font-medium text-ink-dim">caddy</div>
            <pre class="mono overflow-x-auto rounded-lg border border-line bg-surface-2 p-3 text-[11.5px] leading-relaxed text-ink">{{ endpoints.caddy_snippet }}</pre>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { session } from '../store/session'
import { api } from '../api/endpoints'
import CopyField from '../components/CopyField.vue'
import StateView from '../components/StateView.vue'

const loading = ref(true)
const empty = ref('')
const endpoints = ref(null)

const endpointCards = computed(() => {
  if (!endpoints.value) return []
  return [
    { name: 'DoT', port: endpoints.value.dot_port, desc: 'DNS over TLS，端口 853。Android/iOS 私有 DNS 直接使用。', value: endpoints.value.dot_endpoint },
    { name: 'DoH', port: endpoints.value.doh_port, desc: 'DNS over HTTPS，端口 443。浏览器与支持 DoH 的客户端使用。', value: endpoints.value.doh_endpoint },
    { name: 'DoQ', port: endpoints.value.doq_port, desc: 'DNS over QUIC，基于 QUIC 的低延迟加密解析。', value: endpoints.value.doq_endpoint },
  ]
})

const clientGuides = computed(() => {
  if (!endpoints.value) return []
  const c = endpoints.value.clients || {}
  return [
    { title: 'Android 私有 DNS', desc: '设置 → 网络 → 高级 → 私有 DNS → 输入主机名', value: c.android_private_dns || '' },
    { title: 'iOS / iPadOS', desc: '安装描述文件，或使用支持 DoT 的 App 配置', value: c.ios_profile || '' },
    { title: 'dig（DoT）', desc: '命令行验证 DoT 解析', value: c.dig_dot || '' },
    { title: 'curl（DoH）', desc: '命令行验证 DoH 解析', value: c.curl_doh || '' },
  ]
})

onMounted(async () => {
  loading.value = true
  try {
    const id = session.tenantId() // 已兜底 user.tenant_id
    if (!id) {
      empty.value = '当前账号未绑定租户'
      return
    }
    try {
      endpoints.value = await api.endpoints(id)
    } catch (e) {
      if (e.status === 400) {
        empty.value = '尚未定制 DoT 前缀，请先到「设置」页完成前缀定制'
      } else {
        throw e
      }
    }
  } catch (e) {
    empty.value = e.message || '加载失败'
  } finally {
    loading.value = false
  }
})
</script>
