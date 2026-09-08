<template>
  <div class="flex items-center gap-6">
    <svg width="140" height="140" viewBox="0 0 42 42" class="shrink-0">
      <circle cx="21" cy="21" r="15.915" fill="none" stroke="var(--color-surface-2)" stroke-width="5" />
      <circle
        v-for="(seg, i) in segments"
        :key="i"
        cx="21" cy="21" r="15.915" fill="none"
        :stroke="seg.color" stroke-width="5"
        :stroke-dasharray="`${seg.len} ${circ - seg.len}`"
        :stroke-dashoffset="seg.offset"
        :stroke-linecap="i === 0 && segments.length === 1 ? 'round' : 'butt'"
        :transform="i === 0 && segments.length === 1 ? '' : 'rotate(-90 21 21)'"
        style="transition: stroke-dasharray 0.3s ease"
      />
      <text x="21" y="20" text-anchor="middle" class="fill-ink" style="font-size: 8px; font-weight: 700">
        {{ totalLabel }}
      </text>
      <text x="21" y="26" text-anchor="middle" class="fill-ink-faint" style="font-size: 3.5px">总计</text>
    </svg>
    <div class="flex flex-1 flex-col gap-2">
      <div v-for="(d, i) in data" :key="i" class="flex items-center gap-2 text-[12.5px]">
        <span class="h-2.5 w-2.5 rounded-full" :style="{ background: d.color }"></span>
        <span class="flex-1 truncate text-ink-dim">{{ d.label }}</span>
        <span class="tabular-nums text-ink">{{ fmtNum(d.value) }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtNum } from '../utils/format'

const props = defineProps({
  data: { type: Array, default: () => [] }, // [{label, value, color}]
})

const circ = 2 * Math.PI * 15.915

const total = computed(() => props.data.reduce((s, d) => s + (Number(d.value) || 0), 0))
const totalLabel = computed(() => (total.value >= 10000 ? (total.value / 1000).toFixed(1) + 'k' : total.value))

const segments = computed(() => {
  const t = total.value || 1
  let acc = 0
  return props.data.map((d) => {
    const v = Number(d.value) || 0
    const len = (v / t) * circ
    const seg = { color: d.color, len, offset: circ - acc - len + 0 }
    acc += len
    return seg
  })
})
</script>
