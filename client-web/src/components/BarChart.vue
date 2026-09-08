<template>
  <div class="flex flex-col gap-2.5">
    <div v-for="(d, i) in rows" :key="i" class="flex items-center gap-3">
      <div class="w-44 shrink-0 truncate text-[12.5px] text-ink-dim" :title="d.label">{{ d.label }}</div>
      <div class="relative h-5 flex-1 overflow-hidden rounded-md bg-surface-2">
        <div
          class="absolute inset-y-0 left-0 rounded-md transition-all"
          :style="{ width: d.pct + '%', background: color }"
        ></div>
      </div>
      <div class="w-20 shrink-0 text-right text-[12.5px] tabular-nums text-ink">{{ fmt(d.value) }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtNum } from '../utils/format'

const props = defineProps({
  data: { type: Array, default: () => [] }, // [{label, value}]
  color: { type: String, default: 'var(--color-accent)' },
})

const fmt = (v) => fmtNum(v)

const rows = computed(() => {
  const max = Math.max(1, ...props.data.map((d) => Number(d.value) || 0))
  return props.data.map((d) => ({
    label: d.label,
    value: Number(d.value) || 0,
    pct: Math.max(0, ((Number(d.value) || 0) / max) * 100),
  }))
})
</script>
