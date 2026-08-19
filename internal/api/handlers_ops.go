package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"dns-platform/internal/model"
)

// --- upstream groups (上游分流: 组 + 成员 + 规则) ---

func (a *API) listGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := a.repos.ListGroups(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, gs)
}

func (a *API) createGroup(w http.ResponseWriter, r *http.Request) {
	var g model.UpstreamGroup
	if err := readJSON(w, r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if g.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	if err := a.repos.CreateGroup(r.Context(), &g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "group.create", g.Name)
	writeJSON(w, http.StatusCreated, g)
}

func (a *API) updateGroup(w http.ResponseWriter, r *http.Request) {
	var g model.UpstreamGroup
	if err := readJSON(w, r, &g); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	g.ID = r.PathValue("id")
	if err := a.repos.UpdateGroup(r.Context(), &g); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "group.update", g.ID)
	writeJSON(w, http.StatusOK, g)
}

func (a *API) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := a.repos.DeleteGroup(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "group.delete", r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// rejectInternalUpstream blocks upstream addresses that point at internal
// or cloud-metadata networks (SSRF guard). Hostnames are allowed (they are
// resolved by the platform at runtime), IP literals are validated.
func rejectInternalUpstream(u *model.Upstream) error {
	ip := net.ParseIP(u.Address)
	if ip == nil {
		// not an IP literal ? allow (hostname)
		return nil
	}
	// Alibaba / AWS / GCP metadata endpoints
	for _, m := range []string{"100.100.100.200", "169.254.169.254"} {
		if u.Address == m {
			return errors.New("upstream address targets metadata service (blocked)")
		}
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return errors.New("upstream address must be a public IP (blocked internal address)")
	}
	return nil
}

func (a *API) createUpstream(w http.ResponseWriter, r *http.Request) {
	var u model.Upstream
	if err := readJSON(w, r, &u); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if u.Protocol == "" || u.Address == "" || u.GroupID == "" {
		writeErr(w, http.StatusBadRequest, "protocol, address and group_id required")
		return
	}
	if err := rejectInternalUpstream(&u); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.TLSInsecure && a.cfg.Env == "prod" {
		writeErr(w, http.StatusBadRequest, "tls_insecure is forbidden in prod")
		return
	}
	if err := a.repos.CreateUpstream(r.Context(), &u); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "upstream.create", u.Name)
	writeJSON(w, http.StatusCreated, u)
}

func (a *API) updateUpstream(w http.ResponseWriter, r *http.Request) {
	var u model.Upstream
	if err := readJSON(w, r, &u); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u.ID = r.PathValue("id")
	if err := rejectInternalUpstream(&u); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.TLSInsecure && a.cfg.Env == "prod" {
		writeErr(w, http.StatusBadRequest, "tls_insecure is forbidden in prod")
		return
	}
	if err := a.repos.UpdateUpstream(r.Context(), &u); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "upstream.update", u.ID)
	writeJSON(w, http.StatusOK, u)
}

func (a *API) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	if err := a.repos.DeleteUpstream(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "upstream.delete", r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	rs, err := a.repos.ListRules(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	var s model.SplitRule
	if err := readJSON(w, r, &s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if s.GroupID == "" || s.MatchType == "" {
		writeErr(w, http.StatusBadRequest, "group_id and match_type required")
		return
	}
	if err := a.repos.CreateRule(r.Context(), &s); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "rule.create", s.Name)
	writeJSON(w, http.StatusCreated, s)
}

func (a *API) updateRule(w http.ResponseWriter, r *http.Request) {
	var s model.SplitRule
	if err := readJSON(w, r, &s); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.ID = r.PathValue("id")
	if err := a.repos.UpdateRule(r.Context(), &s); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "rule.update", s.ID)
	writeJSON(w, http.StatusOK, s)
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := a.repos.DeleteRule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "rule.delete", r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// reload pushes the latest configuration into the DNS data plane (groups,
// upstreams, rules, hot list). Called automatically after config changes.
func (a *API) reload(w http.ResponseWriter, r *http.Request) {
	if err := a.core.ReloadAll(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.bumpConfig(r.Context())
	a.auditAction(r, "config.reload", "all", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

// bumpConfig signals the data plane (dnsd) to hot-reload configuration.
func (a *API) bumpConfig(ctx context.Context) {
	if a.rdb != nil {
		_ = a.rdb.Incr(ctx, "dns:config:version").Err()
	}
}

func (a *API) afterConfigChange(r *http.Request, action, target string) {
	// data plane reload + audit in one step
	_ = a.core.ReloadAll(r.Context())
	a.bumpConfig(r.Context())
	a.auditAction(r, action, target, "")
}

// --- hot domains ---

func (a *API) listHotDomains(w http.ResponseWriter, r *http.Request) {
	hs, err := a.repos.ListHotDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, hs)
}

func (a *API) createHotDomain(w http.ResponseWriter, r *http.Request) {
	var h model.HotDomain
	if err := readJSON(w, r, &h); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if h.Domain == "" {
		writeErr(w, http.StatusBadRequest, "domain required")
		return
	}
	if err := a.repos.CreateHotDomain(r.Context(), &h); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "hotdomain.create", h.Domain)
	writeJSON(w, http.StatusCreated, h)
}

func (a *API) deleteHotDomain(w http.ResponseWriter, r *http.Request) {
	if err := a.repos.DeleteHotDomain(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.afterConfigChange(r, "hotdomain.delete", r.PathValue("id"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- stats ---

func (a *API) statsOverview(w http.ResponseWriter, r *http.Request) {
	// Prefer live stats pushed by the data plane (dnsd) via Redis.
	if a.rdb != nil {
		if raw, err := a.rdb.Get(r.Context(), "dns:stats:overview").Result(); err == nil && raw != "" {
			var m map[string]any
			if json.Unmarshal([]byte(raw), &m) == nil {
				c := claimsFrom(r)
				if c != nil && c.Role == string(model.RoleTenant) {
					m["tenant_queries"] = a.core.TenantQueries(c.TID)
				}
				writeJSON(w, http.StatusOK, m)
				return
			}
		}
	}
	qps, hitRate, errRate := a.core.Stats().Snapshot()
	tq, th, te := a.core.Stats().Totals()
	hitTotal := 0.0
	errTotal := 0.0
	if tq > 0 {
		hitTotal = float64(th) / float64(tq) * 100.0
		errTotal = float64(te) / float64(tq) * 100.0
	}
	c := claimsFrom(r)
	resp := map[string]any{
		"instance_id":          a.cfg.InstanceID,
		"qps":                  round2(qps),
		"hit_rate_pct":         round2(hitRate),
		"error_rate_pct":       round2(errRate),
		"hit_rate_total_pct":   round2(hitTotal),
		"error_rate_total_pct": round2(errTotal),
		"total_queries":        tq,
		"total_hits":           th,
		"total_errors":         te,
	}
	if c != nil && c.Role == string(model.RoleTenant) {
		resp["tenant_queries"] = a.core.TenantQueries(c.TID)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *API) statsUpstreams(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"by_upstream": a.core.UpstreamQueries(),
		"health":      a.core.UpstreamHealth(),
	})
}

func round2(f float64) float64 {
	return float64(int(f*100)) / 100
}
