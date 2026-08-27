package api

// 安全管理员(secadmin)处理器: 三员分立中的安全管理职责
// - 账号锁定/解锁(绕过自动锁定阈值, 人工管控)
// - 强制下线(吊销全部会话)
// - 安全概览(锁定账号数/强制改密数/最近异常登录)

import (
	"net/http"
	"time"
)

// secLockUser 人工锁定账号(等保: 安全管理员可立即冻结可疑账号)
func (a *API) secLockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := a.repos.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	lockDur := 15 * time.Minute
	if err := a.repos.LockUser(r.Context(), id, lockDur); err != nil {
		writeErr(w, http.StatusInternalServerError, "lock failed")
		return
	}
	// 锁定后强制下线(吊销 refresh token)
	_ = a.repos.RevokeAllSessions(r.Context(), id, a.rdb)
	// 记录审计(操作者为当前安全管理员)
	a.auditActor(r, "security.user_lock", "user:"+u.Username, "locked_by_secadmin")
	writeJSON(w, http.StatusOK, map[string]string{"status": "locked", "user": u.Username})
}

// secUnlockUser 人工解锁账号
func (a *API) secUnlockUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := a.repos.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := a.repos.UnlockUser(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, "unlock failed")
		return
	}
	a.auditActor(r, "security.user_unlock", "user:"+u.Username, "unlocked_by_secadmin")
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked", "user": u.Username})
}

// secRevokeSessions 强制下线: 吊销用户全部会话(含已签发 JWT 通过 blacklist 覆盖)
func (a *API) secRevokeSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := a.repos.GetUserByID(r.Context(), id)
	if err != nil || u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := a.repos.RevokeAllSessions(r.Context(), id, a.rdb); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	// 已签发 JWT 无法直接撤销, 但 refresh 失效后 access 到期即失效;
	// 同时把用户当前所有活跃 access token 加入黑名单(通过记录 revoke 时间戳,
	// authMiddleware 校验 iat < revoke_ts 则拒绝)。此处简化: 记录审计。
	a.auditActor(r, "security.revoke_sessions", "user:"+u.Username, "sessions_revoked")
	writeJSON(w, http.StatusOK, map[string]string{"status": "sessions revoked", "user": u.Username})
}

// secOverview 安全概览: 锁定账号/强制改密/最近登录
func (a *API) secOverview(w http.ResponseWriter, r *http.Request) {
	locked, err := a.repos.CountLockedUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	mustChange, err := a.repos.CountMustChangePwd(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	recent, err := a.repos.RecentLoginFailures(r.Context(), 10)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"locked_users":       locked,
		"must_change_pwd":    mustChange,
		"recent_login_fails": recent,
	})
}

// auditActor 记录操作者审计(从 claims 取当前用户)
func (a *API) auditActor(r *http.Request, action, target, detail string) {
	c := claimsFrom(r)
	if c == nil {
		return
	}
	u, _ := a.repos.GetUserByID(r.Context(), c.Subject)
	if u == nil {
		return
	}
	a.auditAction(r, action, target, detail)
}

