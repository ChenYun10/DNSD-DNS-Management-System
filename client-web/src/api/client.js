// 底层 HTTP 客户端：统一携带 JWT、401 自动续期（refresh token 单次并发去重）。
import { session } from '../store/session'

let refreshing = null

// 一律走同源相对路径，由反向代理转发到后端 apid，前端不感知后端真实地址/端口。
// 如需构建期指定外部反代域名，可设 VITE_API_BASE（仅公开域名，禁止填入内网 apid）。
function baseURL() {
  return import.meta.env.VITE_API_BASE || ''
}

async function request(path, opts = {}) {
  opts = opts || {}
  opts.headers = Object.assign({}, opts.headers || {})
  if (opts.body && typeof opts.body !== 'string') {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(opts.body)
  }
  if (session.accessToken) {
    opts.headers['Authorization'] = 'Bearer ' + session.accessToken
  }

  let res = await fetch(baseURL() + path, opts)

  // 401 且持有 refresh token 且非续期请求本身 → 尝试续期后重试一次
  if (res.status === 401 && session.refreshToken && !opts._retry && !path.startsWith('/api/v1/auth/')) {
    if (!refreshing) {
      refreshing = doRefresh().finally(() => (refreshing = null))
    }
    const ok = await refreshing
    if (ok) {
      return request(path, Object.assign({}, opts, { _retry: true }))
    }
    session.clear()
    // 触发路由守卫回到登录页
    if (window.location.pathname !== '/login') window.location.href = '/login'
    throw new Error('登录已过期，请重新登录')
  }

  const ct = res.headers.get('content-type') || ''
  const body = ct.includes('json') ? await res.json() : await res.text()

  if (!res.ok) {
    const msg = body && body.error ? body.error : 'HTTP ' + res.status
    const err = new Error(msg)
    err.status = res.status
    err.body = body
    throw err
  }
  return body
}

async function doRefresh() {
  try {
    const res = await fetch(baseURL() + '/api/v1/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: session.refreshToken }),
    })
    if (!res.ok) return false
    const j = await res.json()
    session.setTokens(j.access_token, j.refresh_token)
    return true
  } catch {
    return false
  }
}

export const http = {
  get: (p) => request(p),
  post: (p, data) => request(p, { method: 'POST', body: data }),
  put: (p, data) => request(p, { method: 'PUT', body: data }),
  del: (p) => request(p, { method: 'DELETE' }),
}

export function qs(params) {
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params || {})) {
    if (v === undefined || v === null || v === '') continue
    sp.append(k, v)
  }
  const s = sp.toString()
  return s ? '?' + s : ''
}
