<template>
  <div v-if="loading" class="flex items-center justify-center gap-2 py-10 text-ink-dim">
    <svg class="animate-spin" width="18" height="18" viewBox="0 0 24 24" fill="none">
      <circle class="opacity-20" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="3" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" stroke-width="3" stroke-linecap="round" />
    </svg>
    <span class="text-[13px]">加载中…</span>
  </div>
  <div v-else-if="empty" class="flex flex-col items-center justify-center py-12 text-ink-faint">
    <div class="text-3xl">🛰️</div>
    <div class="mt-2 text-[13px]">{{ empty }}</div>
  </div>
</template>

<script setup>
defineProps({
  loading: { type: Boolean, default: false },
  empty: { type: String, default: '' },
})
</script>
