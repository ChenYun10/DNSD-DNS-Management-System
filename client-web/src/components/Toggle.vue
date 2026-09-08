<template>
  <button
    type="button"
    role="switch"
    :aria-checked="modelValue"
    class="relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors"
    :class="modelValue ? 'bg-accent' : 'bg-surface-3'"
    :disabled="disabled"
    @click="emit('update:modelValue', !modelValue)"
  >
    <span
      class="inline-block h-4.5 w-4.5 transform rounded-full bg-white shadow transition-transform"
      :class="modelValue ? 'translate-x-6' : 'translate-x-1'"
      style="height: 18px; width: 18px"
    ></span>
  </button>
</template>

<script setup>
defineProps({
  modelValue: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
})
const emit = defineEmits(['update:modelValue'])
</script>
