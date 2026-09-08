<template>
  <div class="mx-auto max-w-6xl space-y-4 p-4 md:p-6">
    <div>
      <h1 class="text-lg font-semibold">日志</h1>
      <p class="mt-0.5 text-[13px] text-ink-dim">查询日志检索（租户内）</p>
    </div>

    <!-- 筛选 -->
    <div class="card p-4">
      <form class="grid gap-3 md:grid-cols-[1fr_120px_170px_170px_auto] md:items-end" @submit.prevent="search(0)">
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">域名（模糊）</label>
          <input v-model="filters.qname" type="text" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" placeholder="example.com" />
        </div>
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">类型</label>
          <input v-model="filters.qtype" type="text" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" placeholder="A" />
        </div>
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">起始时间</label>
          <input v-model="filters.from" type="datetime-local" class="w-full rounded-lg border border-line bg-surface-2 px-2 py-2 text-[12.5px] outline-none focus:border-accent" />
        </div>
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">结束时间</label>
          <input v-model="filters.to" type="datetime-local" class="w-full rounded-lg border border-line bg-surface-2 px-2 py-2 text-[12.5px] outline-none focus:border-accent" />
        </div>
        <button type="submit" :disabled="loading" class="rounded-lg px-4 py-2 text-[13px] font-semibold text-bg disabled:opacity-50" style="background: linear-gradient(135deg, #34d399, #22d3ee)">
          查询
        </button>
      </form>
    </div>

    <!-- 结果 -->
    <div class="card overflow-hidden">
      <div class="flex items-center justify-between border-b border-line px-4 py-3">
        <div class="text-[12.5px] text-ink-dim">共 <span class="font-semibold text-ink">{{ fmtNum(total) }}</span> 条</div>
        <div class="flex items-center gap-2">
          <select v-model="pageSize" class="rounded-lg border border-line bg-surface-2 px-2 py-1.5 text-[12px] outline-none" @change="search(0)">
            <option :value="20">20 条/页</option>
            <option :value="50">50 条/页</option>
            <option :value="100">100 条/页</option>
          </select>
        </div>
      </div>

      <StateView :loading="loading" :empty="rows.length === 0 && !loading ? '无匹配日志' : ''" />

      <div v-if="rows.length" class="overflow-x-auto">
        <table class="w-full text-left text-[12.5px]">
          <thead class="border-b border-line text-ink-faint">
            <tr>
              <th class="px-4 py-2.5 font-medium">时间</th>
              <th class="px-4 py-2.5 font-medium">域名</th>
              <th class="px-4 py-2.5 font-medium">类型</th>
              <th class="px-4 py-2.5 font-medium">响应码</th>
              <th class="px-4 py-2.5 font-medium">缓存</th>
              <th class="px-4 py-2.5 font-medium">客户端</th>
              <th class="px-4 py-2.5 font-medium">上游</th>
              <th class="px-4 py-2.5 font-medium">RTT</th>
              <th class="px-4 py-2.5 font-medium">协议</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(r, i) in rows" :key="i" class="border-b border-line-soft last:border-0 hover:bg-surface-2/50">
              <td class="mono whitespace-nowrap px-4 py-2 text-ink-dim">{{ fmtTime(r.ts) }}</td>
              <td class="mono px-4 py-2 text-ink">{{ r.qname }}</td>
              <td class="px-4 py-2 text-ink">{{ r.qtype }}</td>
              <td class="px-4 py-2"><span class="rounded px-1.5 py-0.5 text-[11px] font-semibold" :class="rcodeBadge(r.rcode)">{{ r.rcode }}</span></td>
              <td class="px-4 py-2">{{ r.cache_hit ? '✓' : '—' }}</td>
              <td class="mono px-4 py-2 text-ink-dim">{{ r.client_ip }}</td>
              <td class="mono px-4 py-2 text-ink-dim">{{ r.upstream || '—' }}</td>
              <td class="px-4 py-2 tabular-nums text-ink-dim">{{ r.rtt_ms != null ? r.rtt_ms + 'ms' : '—' }}</td>
              <td class="px-4 py-2 text-ink-dim">{{ r.via }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 分页 -->
      <div v-if="total > pageSize" class="flex items-center justify-between border-t border-line px-4 py-3">
        <button :disabled="page <= 0" class="rounded-lg border border-line px-3 py-1.5 text-[12.5px] text-ink-dim transition-colors hover:bg-surface-2 disabled:opacity-40" @click="search(page - 1)">
          ← 上一页
        </button>
        <span class="text-[12.5px] text-ink-dim">第 {{ page + 1 }} / {{ totalPages }} 页</span>
        <button :disabled="page + 1 >= totalPages" class="rounded-lg border border-line px-3 py-1.5 text-[12.5px] text-ink-dim transition-colors hover:bg-surface-2 disabled:opacity-40" @click="search(page + 1)">
          下一页 →
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api/endpoints'
import { session } from '../store/session'
import { fmtNum, fmtTime } from '../utils/format'
import StateView from '../components/StateView.vue'

const filters = reactive({ qname: '', qtype: '', from: '', to: '' })
const rows = ref([])
const total = ref(0)
const page = ref(0)
const pageSize = ref(50)
const loading = ref(false)

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value)))

function toApiTime(s) {
  return s ? s.replace('T', ' ') + ':00' : ''
}

function rcodeBadge(rcode) {
  const m = { NOERROR: 'bg-accent/15 text-accent', NXDOMAIN: 'bg-warn/15 text-warn', SERVFAIL: 'bg-danger/15 text-danger' }
  return m[rcode] || 'bg-surface-3 text-ink-dim'
}

async function search(p) {
  loading.value = true
  try {
    const res = await api.queryLogs({
      tenant_id: session.tenantId(),
      qname: filters.qname || undefined,
      qtype: filters.qtype || undefined,
      from: filters.from ? toApiTime(filters.from) : undefined,
      to: filters.to ? toApiTime(filters.to) : undefined,
      limit: pageSize.value,
      offset: p * pageSize.value,
    })
    rows.value = res.rows || []
    total.value = res.total || 0
    page.value = p
  } catch (e) {
    rows.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

onMounted(() => search(0))
</script>
