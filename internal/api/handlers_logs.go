package api

import (
	"net/http"
	"strconv"
	"time"

	"dns-platform/internal/model"
)

// queryLogs returns paged query logs from MySQL (tenant users see only their
// own tenant; admins can filter any tenant).
func (a *API) queryLogs(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	tenantID := r.URL.Query().Get("tenant_id")
	// 权限分明: 租户用户强制只看自己租户;
	// 管理角色(admin/sysadmin/secadmin/auditadmin): 绑定了租户则默认看自己租户, 未绑定看全部
	switch model.Role(c.Role) {
	case model.RoleTenant:
		tenantID = c.TID // 强制租户隔离
	case model.RoleAdmin, model.RoleSysAdmin, model.RoleSecAdmin, model.RoleAuditAdmin:
		if tenantID == "" {
			tenantID = c.TID // 管理员绑定租户时默认看自己租户(可显式传空看全部)
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	rows, total, err := a.mysql.QueryLogs(r.Context(),
		tenantID,
		r.URL.Query().Get("qname"),
		r.URL.Query().Get("qtype"),
		r.URL.Query().Get("from"),
		r.URL.Query().Get("to"),
		limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "rows": rows})
}

func (a *API) queryAudit(w http.ResponseWriter, r *http.Request) {
	rows, err := a.mysql.QueryAudit(r.Context(), r.URL.Query().Get("action"), 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

// verifyAuditChain 校验审计日志哈希链完整性(等保: 审计日志防篡改验证)
// 返回: ok=true 链完整; ok=false 时 break_id 为被篡改的第一条日志 ID
func (a *API) verifyAuditChain(w http.ResponseWriter, r *http.Request) {
	ok, breakID, err := a.mysql.VerifyAuditChain(r.Context(), 100000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          ok,
		"break_id":    breakID,
		"checked_max": 100000,
		"ts":          time.Now(),
	})
}

var _ = time.Now
