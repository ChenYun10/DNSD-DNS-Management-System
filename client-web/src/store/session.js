import { reactive } from 'vue'

const ACCESS_KEY = 'dnsd_access_token'
const REFRESH_KEY = 'dnsd_refresh_token'

function read(key) {
  try {
    return localStorage.getItem(key) || ''
  } catch {
    return ''
  }
}

export const session = reactive({
  accessToken: read(ACCESS_KEY),
  refreshToken: read(REFRESH_KEY),
  user: null,
  tenant: null,

  setTokens(access, refresh) {
    this.accessToken = access || ''
    this.refreshToken = refresh || ''
    try {
      if (access) localStorage.setItem(ACCESS_KEY, access)
      else localStorage.removeItem(ACCESS_KEY)
      if (refresh) localStorage.setItem(REFRESH_KEY, refresh)
      else localStorage.removeItem(REFRESH_KEY)
    } catch {
      /* ignore */
    }
  },

  setProfile(user, tenant) {
    this.user = user || null
    this.tenant = tenant || null
  },

  clear() {
    this.setTokens('', '')
    this.user = null
    this.tenant = null
  },

  isAuthed() {
    return !!this.accessToken
  },

  tenantId() {
    return (this.tenant && this.tenant.id) || (this.user && this.user.tenant_id) || ''
  },

  isTenantRole() {
    return this.user && this.user.role === 'tenant'
  },

  isAdmin() {
    return this.user && (this.user.role === 'admin' || this.user.role === 'sysadmin')
  },
})
