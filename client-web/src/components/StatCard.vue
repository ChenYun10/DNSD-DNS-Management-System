<template>
  <div class="card p-5">
    <div class="flex items-center justify-between">
      <div class="text-[12px] font-medium uppercase tracking-wide text-ink-dim">{{ label }}</div>
    </div>
    <div class="mt-2 flex items-baseline gap-2">
      <span class="text-2xl font-semibold tabular-nums">{{ value }}</span>
      <span v-if="unit" class="text-[13px] text-ink-dim">{{ unit }}</span>
    </div>
    <div v-if="hint" class="mt-1 text-[12px] text-ink-faint">{{ hint }}</div>
  </div>
</template>

<script setup>
defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '—' },
  unit: { type: String, default: '' },
  hint: { type: String, default: '' },
})
</script>
