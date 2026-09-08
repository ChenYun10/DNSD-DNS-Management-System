<template>
  <div class="mx-auto max-w-6xl space-y-6 p-4 md:p-6">
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-lg font-semibold">分析</h1>
        <p class="mt-0.5 text-[13px] text-ink-dim">查询概况与解析分布（基于最近查询日志聚合）</p>
      </div>
      <button class="rounded-lg border border-line px-3 py-1.5 text-[12.5px] font-medium text-ink-dim transition-colors hover:bg-surface-2 hover:text-ink" @click="loadAll">
        ↻ 刷新
      </button>
    </div>

    <!-- 统计卡片 -->
    <div class="grid grid-cols-2 gap-4 lg:grid-cols-5">
      <StatCard label="实时 QPS" :value="fmtNum(overview.qps)" unit="q/s" />
      <StatCard label="缓存命中率" :value="fmtPct(overview.hit_rate_pct)" hint="近 5s 快照" />
      <StatCard label="错误率" :value="fmtPct(overview.error_rate_pct)" />
      <StatCard label="累计查询" :value="fmtNum(overview.total_queries)" />
      <StatCard label="本租户查询" :value="fmtNum(overview.tenant_queries ?? overview.total_queries)" />
    </div>

    <!-- 活跃客户端 -->
    <div class="card p-5">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-[14px] font-semibold">活跃客户端</h2>
          <p class="mt-0.5 text-[12px] text-ink-dim">正在使用本 DNS 服务的客户端（按源 IP 聚合最近查询）</p>
        </div>
        <div class="flex items-center gap-2">
          <span class="flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-2.5 py-1 text-[12px] text-accent">
            <span class="h-2 w-2 rounded-full bg-accent"></span>
            使用中 {{ activeCount }}
          </span>
          <span class="rounded-full border border-line bg-surface-2 px-2.5 py-1 text-[12px] text-ink-dim">共 {{ activeClients.length }}</span>
        </div>
      </div>

      <div v-if="activeClients.length" class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-[12.5px]">
          <thead class="border-b border-line text-ink-faint">
            <tr>
              <th class="py-2 pr-4 font-medium">状态</th>
              <th class="py-2 pr-4 font-medium">客户端 IP</th>
              <th class="py-2 pr-4 font-medium">查询次数</th>
              <th class="py-2 font-medium">最后活跃</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in activeClients" :key="c.ip" class="border-b border-line-soft last:border-0">
              <td class="py-2 pr-4">
                <span class="inline-flex items-center gap-1.5">
                  <span class="h-2 w-2 rounded-full" :class="c.online ? 'bg-accent' : 'bg-ink-faint'"></span>
                  <span :class="c.online ? 'text-accent' : 'text-ink-faint'">{{ c.online ? '使用中' : '离线' }}</span>
                </span>
              </td>
              <td class="mono py-2 pr-4 text-ink">{{ c.ip }}</td>
              <td class="py-2 pr-4 tabular-nums text-ink">{{ fmtNum(c.count) }}</td>
              <td class="py-2 text-ink-dim">{{ fmtAgo(c.last) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-else class="mt-3 text-[12.5px] text-ink-faint">暂无客户端查询记录</div>
    </div>

    <!-- 图表区 -->
    <div class="grid gap-4 lg:grid-cols-2">
      <div class="card p-5">
        <h2 class="text-[13px] font-medium text-ink-dim">查询趋势</h2>
        <div class="mt-3">
          <LineChart :data="trend" :labels="trendLabels" />
        </div>
      </div>
      <div class="card p-5">
        <h2 class="text-[13px] font-medium text-ink-dim">响应码分布</h2>
        <div class="mt-4">
          <DonutChart :data="rcodeData" />
        </div>
      </div>
      <div class="card p-5">
        <h2 class="text-[13px] font-medium text-ink-dim">热门域名 Top 10</h2>
        <div class="mt-4">
          <BarChart :data="topDomains" />
        </div>
      </div>
      <div class="card p-5">
        <h2 class="text-[13px] font-medium text-ink-dim">上游节点分布</h2>
        <div class="mt-4">
          <BarChart :data="upstreamDist" color="var(--color-accent-2)" />
        </div>
      </div>
    </div>

    <!-- ECS 模拟诊断 -->
    <div class="card p-5">
      <h2 class="text-[14px] font-semibold">解析诊断（ECS 模拟）</h2>
      <p class="mt-1 text-[12px] text-ink-dim">模拟任意子网发起查询，查看缓存 → 分流 → 上游 → DNSSEC 的完整解析路径。</p>

      <form class="mt-4 grid gap-3 md:grid-cols-[1fr_120px_200px_auto_auto] md:items-end" @submit.prevent="onSimulate">
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">域名</label>
          <input v-model="sim.qname" type="text" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" placeholder="example.com" required />
        </div>
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">类型</label>
          <select v-model="sim.qtype" class="w-full rounded-lg border border-line bg-surface-2 px-2 py-2 text-[13px] outline-none focus:border-accent">
            <option>A</option><option>AAAA</option><option>CNAME</option><option>MX</option><option>TXT</option><option>NS</option><option>SOA</option><option>HTTPS</option>
          </select>
        </div>
        <div>
          <label class="mb-1 block text-[12px] text-ink-dim">ECS 子网（可选）</label>
          <input v-model="sim.ecs" type="text" class="w-full rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] outline-none focus:border-accent" placeholder="203.0.113.0/24" />
        </div>
        <label class="flex items-center gap-2 pb-2 text-[12px] text-ink-dim">
          <input v-model="sim.flush" type="checkbox" class="accent-emerald-400" /> 清缓存
        </label>
        <button type="submit" :disabled="simulating" class="rounded-lg px-4 py-2 text-[13px] font-semibold text-bg disabled:opacity-50" style="background: linear-gradient(135deg, #34d399, #22d3ee)">
          {{ simulating ? '解析中…' : '模拟解析' }}
        </button>
      </form>

      <!-- 模拟结果 -->
      <div v-if="simResult" class="mt-5 rounded-lg border border-line-soft bg-surface-2 p-4">
        <div class="flex flex-wrap items-center gap-2">
          <span class="mono text-[13px] font-medium text-ink">{{ simResult.qname }} {{ simResult.qtype }}</span>
          <span class="rounded-md px-2 py-0.5 text-[11px] font-semibold" :class="simResult.cache_hit ? 'bg-accent/15 text-accent' : 'bg-surface-3 text-ink-dim'">
            {{ simResult.cache_hit ? '缓存命中' : '缓存未命中' }}
          </span>
          <span class="rounded-md bg-surface-3 px-2 py-0.5 text-[11px] font-semibold" :class="rcodeColor(simResult.rcode)">
            {{ simResult.rcode }}
          </span>
          <span v-if="simResult.dnssec_validated" class="rounded-md bg-accent-2/15 px-2 py-0.5 text-[11px] font-semibold text-accent-2">DNSSEC ✓</span>
          <span class="ml-auto text-[12px] text-ink-dim">RTT {{ fmtRtt(simResult.rtt_ms) }}</span>
        </div>

        <div class="mt-3 grid gap-3 text-[12.5px] sm:grid-cols-3">
          <div><span class="text-ink-faint">上游组：</span><span class="text-ink">{{ simResult.upstream_group || '—' }}</span></div>
          <div><span class="text-ink-faint">上游节点：</span><span class="mono text-ink">{{ simResult.upstream || '—' }}</span></div>
          <div><span class="text-ink-faint">命中规则：</span><span class="text-ink">{{ simResult.rule_matched || '—' }}</span></div>
          <div v-if="simResult.ecs_used"><span class="text-ink-faint">实际 ECS：</span><span class="mono text-ink">{{ simResult.ecs_used }}</span></div>
        </div>

        <div v-if="simResult.answers && simResult.answers.length" class="mt-4">
          <div class="mb-2 text-[12px] font-medium text-ink-dim">应答记录（{{ simResult.answers.length }}）</div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-[12.5px]">
              <thead class="text-ink-faint">
                <tr><th class="py-1 pr-4 font-medium">名称</th><th class="py-1 pr-4 font-medium">类型</th><th class="py-1 pr-4 font-medium">TTL</th><th class="py-1 font-medium">数据</th></tr>
              </thead>
              <tbody class="text-ink">
                <tr v-for="(a, i) in simResult.answers" :key="i" class="border-t border-line-soft">
                  <td class="mono py-1.5 pr-4">{{ a.name }}</td>
                  <td class="py-1.5 pr-4">{{ a.type }}</td>
                  <td class="py-1.5 pr-4">{{ a.ttl }}</td>
                  <td class="mono py-1.5 break-all">{{ a.data }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
      <div v-if="simError" class="mt-4 rounded-lg border border-danger/30 bg-danger/10 px-3 py-2 text-[12.5px] text-danger">{{ simError }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { api } from '../api/endpoints'
import { session } from '../store/session'
import { fmtNum, fmtPct, fmtRtt, shortTs, fmtAgo } from '../utils/format'
import StatCard from '../components/StatCard.vue'
import LineChart from '../components/LineChart.vue'
import BarChart from '../components/BarChart.vue'
import DonutChart from '../components/DonutChart.vue'

const overview = reactive({ qps: 0, hit_rate_pct: 0, error_rate_pct: 0, total_queries: 0, tenant_queries: 0 })
const logs = ref([])

const sim = reactive({ qname: '', qtype: 'A', ecs: '', flush: false })
const simulating = ref(false)
const simResult = ref(null)
const simError = ref('')

// --- 聚合 ---
const trend = computed(() => {
  const buckets = 20
  const sorted = [...logs.value].sort((a, b) => new Date(a.ts) - new Date(b.ts))
  if (sorted.length === 0) return []
  const min = new Date(sorted[0].ts).getTime()
  const max = new Date(sorted[sorted.length - 1].ts).getTime()
  const span = Math.max(1, max - min)
  const counts = new Array(buckets).fill(0)
  for (const r of sorted) {
    const t = new Date(r.ts).getTime()
    const idx = Math.min(buckets - 1, Math.floor(((t - min) / span) * buckets))
    counts[idx]++
  }
  return counts.map((v, i) => ({ label: '', value: v }))
})

const trendLabels = computed(() => {
  const sorted = [...logs.value].sort((a, b) => new Date(a.ts) - new Date(b.ts))
  if (sorted.length === 0) return []
  const labels = []
  for (let i = 0; i < 3; i++) {
    const idx = Math.min(sorted.length - 1, Math.floor((i / 2) * (sorted.length - 1)))
    labels.push(shortTs(sorted[idx].ts))
  }
  return labels
})

const topDomains = computed(() => {
  const m = new Map()
  for (const r of logs.value) {
    const k = r.qname || '(unknown)'
    m.set(k, (m.get(k) || 0) + 1)
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, value]) => ({ label, value }))
})

const rcodeData = computed(() => {
  const colors = { NOERROR: '#34d399', NXDOMAIN: '#fbbf24', SERVFAIL: '#f87171', REFUSED: '#f472b6' }
  const m = new Map()
  for (const r of logs.value) m.set(r.rcode || 'OTHER', (m.get(r.rcode || 'OTHER') || 0) + 1)
  return [...m.entries()].map(([label, value]) => ({ label, value, color: colors[label] || '#64748b' }))
})

const upstreamDist = computed(() => {
  const m = new Map()
  for (const r of logs.value) {
    const k = r.upstream || r.upstream_group || '(cache/unknown)'
    m.set(k, (m.get(k) || 0) + 1)
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([label, value]) => ({ label, value }))
})

// 活跃客户端：按 client_ip 聚合最近查询，"正在使用"= 最后活跃在 5 分钟内
const ACTIVE_WINDOW_MS = 5 * 60 * 1000
const activeClients = computed(() => {
  const now = Date.now()
  const m = new Map()
  for (const r of logs.value) {
    const ip = r.client_ip || '(未知)'
    const ts = new Date(r.ts).getTime()
    const e = m.get(ip) || { ip, count: 0, last: 0 }
    e.count++
    if (ts > e.last) e.last = ts
    m.set(ip, e)
  }
  return [...m.values()]
    .sort((a, b) => b.last - a.last)
    .map((e) => ({ ...e, online: now - e.last < ACTIVE_WINDOW_MS }))
})

const activeCount = computed(() => activeClients.value.filter((c) => c.online).length)

function rcodeColor(rcode) {
  const c = { NOERROR: 'text-accent', NXDOMAIN: 'text-warn', SERVFAIL: 'text-danger' }
  return c[rcode] || 'text-ink-dim'
}

async function loadAll() {
  try {
    const s = await api.statsOverview()
    Object.assign(overview, s)
  } catch {
    /* 统计失败不阻断 */
  }
  try {
    const res = await api.queryLogs({ limit: 500, tenant_id: session.tenantId() })
    logs.value = res.rows || []
  } catch {
    logs.value = []
  }
}

async function onSimulate() {
  simulating.value = true
  simResult.value = null
  simError.value = ''
  try {
    simResult.value = await api.simulate({
      qname: sim.qname,
      qtype: sim.qtype,
      ecs: sim.ecs || undefined,
      flush: sim.flush || undefined,
    })
  } catch (e) {
    simError.value = e.message || '模拟失败'
  } finally {
    simulating.value = false
  }
}

onMounted(loadAll)
</script>
