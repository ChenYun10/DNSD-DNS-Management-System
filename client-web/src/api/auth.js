import { http } from './client'

export const auth = {
  login(username, password) {
    return http.post('/api/v1/auth/login', { username, password })
  },
  logout() {
    return http.post('/api/v1/auth/logout', {})
  },
  me() {
    return http.get('/api/v1/me')
  },
  changePassword(oldPassword, newPassword) {
    return http.post('/api/v1/auth/change-password', {
      old_password: oldPassword,
      new_password: newPassword,
    })
  },
}
