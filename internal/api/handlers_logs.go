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

var _ = time.Now
