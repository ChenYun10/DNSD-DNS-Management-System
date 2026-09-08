<template>
  <div class="group flex items-center gap-2 rounded-lg border border-line bg-surface-2 px-3 py-2.5">
    <div class="mono min-w-0 flex-1 truncate text-[12.5px] text-ink" :title="value">{{ value }}</div>
    <button
      class="shrink-0 rounded-md px-2 py-1 text-[11px] font-medium text-ink-dim transition-colors hover:bg-surface-3 hover:text-ink"
      @click="onCopy"
    >
      {{ copied ? '已复制' : '复制' }}
    </button>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { copyText } from '../utils/format'

const props = defineProps({
  value: { type: String, required: true },
})

const copied = ref(false)

async function onCopy() {
  await copyText(props.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}
</script>
