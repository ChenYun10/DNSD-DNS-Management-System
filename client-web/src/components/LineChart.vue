<template>
  <div>
    <svg :viewBox="`0 0 ${W} ${H}`" class="w-full" preserveAspectRatio="none" :style="{ height: height + 'px' }">
      <defs>
        <linearGradient :id="gid" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" :stop-color="color" stop-opacity="0.25" />
          <stop offset="100%" :stop-color="color" stop-opacity="0" />
        </linearGradient>
      </defs>
      <!-- 网格线 -->
      <line v-for="i in 4" :key="i" :x1="padL" :x2="W - padR" :y1="padT + (i * innerH) / 4" :y2="padT + (i * innerH) / 4" stroke="var(--color-line)" stroke-width="1" />
      <!-- 面积 -->
      <path v-if="linePath" :d="areaPath" :fill="`url(#${gid})`" stroke="none" />
      <!-- 折线 -->
      <path v-if="linePath" :d="linePath" fill="none" :stroke="color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />
      <!-- 数据点 -->
      <circle v-for="(p, i) in points" :key="i" :cx="p.x" :cy="p.y" r="2.5" :fill="color">
        <title>{{ labels[i] }}：{{ data[i].value }}</title>
      </circle>
    </svg>
    <!-- X 轴标签 -->
    <div class="mt-1 flex justify-between text-[10px] text-ink-faint">
      <span v-if="labels[0]">{{ labels[0] }}</span>
      <span v-if="labels.length > 1">{{ labels[Math.floor(labels.length / 2)] }}</span>
      <span v-if="labels.length > 2">{{ labels[labels.length - 1] }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  data: { type: Array, default: () => [] }, // [{label, value}]
  labels: { type: Array, default: () => [] },
  color: { type: String, default: '#34d399' },
  height: { type: Number, default: 180 },
})

const W = 600
const H = 180
const padL = 6
const padR = 6
const padT = 10
const padB = 8
const innerW = W - padL - padR
const innerH = H - padT - padB

const gid = 'grad-' + Math.random().toString(36).slice(2, 8)

const values = computed(() => props.data.map((d) => Number(d.value) || 0))
const max = computed(() => Math.max(1, ...values.value))
const min = computed(() => Math.min(0, ...values.value))

const points = computed(() => {
  const n = props.data.length
  if (n === 0) return []
  return props.data.map((d, i) => {
    const x = n === 1 ? W / 2 : padL + (i / (n - 1)) * innerW
    const v = Number(d.value) || 0
    const range = max.value - min.value || 1
    const y = padT + (1 - (v - min.value) / range) * innerH
    return { x, y }
  })
})

const linePath = computed(() => {
  if (points.value.length === 0) return ''
  return points.value.map((p, i) => (i === 0 ? `M ${p.x} ${p.y}` : `L ${p.x} ${p.y}`)).join(' ')
})

const areaPath = computed(() => {
  if (points.value.length === 0) return ''
  const first = points.value[0]
  const last = points.value[points.value.length - 1]
  const base = padT + innerH
  return `${linePath.value} L ${last.x} ${base} L ${first.x} ${base} Z`
})
</script>
