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
	if c.Role != string(model.RoleAdmin) {
		tenantID = c.TID // forced scoping
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	// 性能保护:前端未指定时间范围时默认最近 24h(表有数百万行,全量扫描会拖垮查询)
	// 注意:dnsd 数据面落库的 ts 是 UTC,默认窗口必须用 UTC 计算。
	// 若用本地时间(CST)算,窗口与数据错位 8 小时,实际覆盖 ~40h 数据,
	// 24h 窗口会命中 ~95% 的行(开放递归流量 8.6M 行/天),COUNT 变成全表扫描。
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	if from == "" && to == "" {
		from = time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	rows, total, err := a.mysql.QueryLogs(r.Context(),
		tenantID,
		r.URL.Query().Get("qname"),
		r.URL.Query().Get("qtype"),
		from, to,
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

var _ = time.Now
