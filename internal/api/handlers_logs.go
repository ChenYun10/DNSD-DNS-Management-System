package api

import (
	"net/http"
	"strconv"
	"strings"
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
		// 租户用户必须绑定租户；未绑定时拒绝，避免读到全平台日志
		if c.TID == "" {
			writeErr(w, http.StatusForbidden, "tenant user has no tenant binding")
			return
		}
		tenantID = c.TID // 强制租户隔离
	case model.RoleAdmin, model.RoleSysAdmin:
		if tenantID == "" {
			tenantID = c.TID // 管理员绑定租户时默认看自己租户(可显式传空看全部)
		}
	default:
		// secadmin/auditadmin 无查询日志读取权限(三员分立), 防御纵深
		writeErr(w, http.StatusForbidden, "insufficient role")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	if a.cfg.LogQueryMaxOffset > 0 && offset > a.cfg.LogQueryMaxOffset {
		offset = a.cfg.LogQueryMaxOffset
	}
	from, to := a.windowBounds(r.URL.Query().Get("from"), r.URL.Query().Get("to"))

	rows, total, err := a.mysql.QueryLogs(r.Context(),
		tenantID,
		r.URL.Query().Get("qname"),
		r.URL.Query().Get("qtype"),
		from, to,
		limit, offset, a.cfg.LogQueryCountCap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "rows": rows})
}

// windowBounds 兜底并约束查询时间窗：from/to 为空时使用默认窗口（避免无时间
// 约束扫全库），跨度超过上限则截断；返回 MySQL 友好的 "YYYY-MM-DD HH:MM:SS"。
func (a *API) windowBounds(from, to string) (string, string) {
	now := time.Now()
	defaultWindow := a.cfg.LogQueryDefaultWindow
	if defaultWindow <= 0 {
		defaultWindow = 24 * time.Hour
	}
	parse := func(s string) (time.Time, bool) {
		if s == "" {
			return time.Time{}, false
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.ReplaceAll(s, "T", " "), time.Local)
		if err != nil {
			return time.Time{}, false
		}
		return t, true
	}
	ft, okFrom := parse(from)
	tt, okTo := parse(to)
	if !okFrom {
		ft = now.Add(-defaultWindow)
	}
	if !okTo {
		tt = now
	}
	if a.cfg.LogQueryMaxWindow > 0 && tt.Sub(ft) > a.cfg.LogQueryMaxWindow {
		ft = tt.Add(-a.cfg.LogQueryMaxWindow)
	}
	if tt.Before(ft) {
		ft, tt = tt, ft
	}
	const layout = "2006-01-02 15:04:05"
	return ft.Format(layout), tt.Format(layout)
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
