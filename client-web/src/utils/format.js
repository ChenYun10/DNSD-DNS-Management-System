// 展示层格式化工具

export function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  const p = (n) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function fmtNum(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '0'
  return Number(n).toLocaleString('zh-CN')
}

export function fmtRtt(ms) {
  if (ms === null || ms === undefined) return '—'
  if (ms < 1000) return ms + ' ms'
  return (ms / 1000).toFixed(2) + ' s'
}

export function fmtPct(v) {
  if (v === null || v === undefined) return '—'
  return Number(v).toFixed(1) + '%'
}

export function shortTs(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return String(ts)
  const p = (n) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

export function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text)
  }
  // fallback
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.select()
  try {
    document.execCommand('copy')
  } finally {
    document.body.removeChild(ta)
  }
  return Promise.resolve()
}

export function rcodeLabel(rcode) {
  const map = {
    NOERROR: '成功',
    NXDOMAIN: '域名不存在',
    SERVFAIL: '服务失败',
    REFUSED: '拒绝',
    FORMERR: '格式错误',
    NOTIMP: '未实现',
  }
  return map[rcode] || rcode || '—'
}

// 相对时间（用于"最后活跃 X 分钟前"）
export function fmtAgo(ts) {
  if (!ts) return '—'
  const t = new Date(ts).getTime()
  if (Number.isNaN(t)) return '—'
  let diff = Date.now() - t
  if (diff < 0) diff = 0
  if (diff < 60_000) return '刚刚'
  if (diff < 3_600_000) return Math.floor(diff / 60_000) + ' 分钟前'
  if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + ' 小时前'
  return Math.floor(diff / 86_400_000) + ' 天前'
}
