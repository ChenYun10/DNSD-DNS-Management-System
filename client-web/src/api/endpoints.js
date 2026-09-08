import { http, qs } from './client'

// 租户自助门户可用的业务端点（与 apid 租户 RBAC 对齐）
export const api = {
  // 系统信息（公开）
  systemInfo() {
    return http.get('/api/v1/system/info')
  },

  // --- 租户 ---
  tenant(id) {
    return http.get('/api/v1/tenants/' + id)
  },
  updateTenant(id, payload) {
    return http.put('/api/v1/tenants/' + id, payload)
  },
  customizeDot(id, payload) {
    return http.post('/api/v1/tenants/' + id + '/dot', payload)
  },
  endpoints(id) {
    return http.get('/api/v1/tenants/' + id + '/endpoints')
  },
  tenantStats(id) {
    return http.get('/api/v1/tenants/' + id + '/stats')
  },
  warmTenant(id) {
    return http.post('/api/v1/tenants/' + id + '/warm', {})
  },

  // --- 诊断 ---
  simulate(payload) {
    return http.post('/api/v1/dns/simulate', payload)
  },

  // --- 日志 ---
  queryLogs(params) {
    return http.get('/api/v1/logs/query' + qs(params))
  },

  // --- 统计 ---
  statsOverview() {
    return http.get('/api/v1/stats/overview')
  },
}
