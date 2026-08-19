package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

// scopeTenant enforces tenant-scoped RBAC: admins access any tenant;
// tenant users only their own. Returns 403 otherwise.
func (a *API) scopeTenant(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := claimsFrom(r)
		if c == nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id := r.PathValue("id")
		if c.Role != string(model.RoleAdmin) && c.TID != id {
			writeErr(w, http.StatusForbidden, "not your tenant")
			return
		}
		next(w, r)
	}
}

func (a *API) listTenants(w http.ResponseWriter, r *http.Request) {
	ts, err := a.repos.ListTenants(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ts)
}

func (a *API) getTenant(w http.ResponseWriter, r *http.Request) {
	t, err := a.repos.GetTenant(r.Context(), r.PathValue("id"))
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request) {
	var t model.Tenant
	if err := readJSON(w, r, &t); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if t.Name == "" || t.Prefix == "" || t.BaseDomain == "" {
		writeErr(w, http.StatusBadRequest, "name, prefix and base_domain required")
		return
	}
	if !store.ValidPrefix(t.Prefix) {
		writeErr(w, http.StatusBadRequest, "invalid prefix: 3-32 lowercase alnum/hyphen, not reserved")
		return
	}
	if t.RateLimitQPS == 0 {
		t.RateLimitQPS = a.cfg.RateLimitQPS
	}
	if t.CacheMaxTTL == 0 {
		t.CacheMaxTTL = int(a.cfg.CacheMaxTTL.Seconds())
	}
	if err := a.repos.CreateTenant(r.Context(), &t); err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			writeErr(w, http.StatusConflict, "prefix or id already exists")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// default: tenant admin user with same name
	_ = a.repos.CreateUser(r.Context(), &model.User{
		ID:       uuid.NewString(),
		TenantID: t.ID,
		Username: t.Name + "-admin",
		Role:     model.RoleTenant,
	}, randomPassword())
	a.bumpConfig(r.Context())
	a.auditAction(r, "tenant.create", "tenant:"+t.ID, t)
	writeJSON(w, http.StatusCreated, t)
}

func (a *API) updateTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := a.repos.GetTenant(r.Context(), id)
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	var in model.Tenant
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// tenant users may only toggle their own protocol flags; prefix changes
	// go through /dot (audited separately)
	c := claimsFrom(r)
	if c.Role != string(model.RoleAdmin) {
		t.DoTEnabled = in.DoTEnabled
		t.DoHEnabled = in.DoHEnabled
		t.DoQEnabled = in.DoQEnabled
	} else {
		t.Name = in.Name
		t.Prefix = in.Prefix
		t.BaseDomain = in.BaseDomain
		t.Enabled = in.Enabled
		t.VIP = in.VIP
		t.RateLimitQPS = in.RateLimitQPS
		t.CacheMaxTTL = in.CacheMaxTTL
		t.DefaultECS = in.DefaultECS
		t.AllowECS = in.AllowECS
		t.DoTEnabled = in.DoTEnabled
		t.DoHEnabled = in.DoHEnabled
		t.DoQEnabled = in.DoQEnabled
		t.UpstreamGroup = in.UpstreamGroup
	}
	if err := a.repos.UpdateTenant(r.Context(), t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.repos.PurgeMetaCache(r.Context())
	a.bumpConfig(r.Context())
	a.auditAction(r, "tenant.update", "tenant:"+id, t)
	writeJSON(w, http.StatusOK, t)
}

func (a *API) deleteTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.repos.DeleteTenant(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.repos.PurgeMetaCache(r.Context())
	a.bumpConfig(r.Context())
	a.auditAction(r, "tenant.delete", "tenant:"+id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// customizeDot implements DoT 前缀定制: a tenant (or admin on their behalf)
// customizes the DoT prefix and protocol availability.
func (a *API) customizeDot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := a.repos.GetTenant(r.Context(), id)
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	var in struct {
		Prefix     string `json:"prefix"`
		DoTEnabled *bool  `json:"dot_enabled"`
		DoHEnabled *bool  `json:"doh_enabled"`
		DoQEnabled *bool  `json:"doq_enabled"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if in.Prefix != "" {
		if !store.ValidPrefix(in.Prefix) {
			writeErr(w, http.StatusBadRequest, "invalid prefix: 3-32 lowercase alnum/hyphen, not reserved")
			return
		}
		// uniqueness check
		existing, err := a.repos.TenantByPrefix(r.Context(), in.Prefix)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if existing != nil && existing.ID != t.ID {
			writeErr(w, http.StatusConflict, "prefix already taken")
			return
		}
		t.Prefix = in.Prefix
	}
	if in.DoTEnabled != nil {
		t.DoTEnabled = *in.DoTEnabled
	}
	if in.DoHEnabled != nil {
		t.DoHEnabled = *in.DoHEnabled
	}
	if in.DoQEnabled != nil {
		t.DoQEnabled = *in.DoQEnabled
	}
	if err := a.repos.UpdateTenant(r.Context(), t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.repos.PurgeMetaCache(r.Context())
	a.auditAction(r, "tenant.dot_customize", "tenant:"+id, map[string]any{"prefix": t.Prefix, "dot": t.DoTEnabled, "doh": t.DoHEnabled, "doq": t.DoQEnabled})
	writeJSON(w, http.StatusOK, t)
}

// tenantEndpoints returns the deployable DoT/DoH/DoQ endpoints plus
// ready-to-use client configs (Android Private DNS, iOS profile, dig/curl).
func (a *API) tenantEndpoints(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := a.repos.GetTenant(r.Context(), id)
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	if t.Prefix == "" {
		writeErr(w, http.StatusBadRequest, "tenant has no prefix yet — customize it first")
		return
	}
	ep := map[string]any{
		"tenant_id":    t.ID,
		"prefix":       t.Prefix,
		"dot_endpoint": t.DotEndpoint(),
		"doh_endpoint": t.DoHEndpoint(),
		"doq_endpoint": "quic://" + t.DotEndpoint(),
		"dot_port":     853,
		"doh_port":     443,
		"doq_port":     853,
		"clients": map[string]string{
			"android_private_dns": t.DotEndpoint(),
			"ios_profile":         "DoT " + t.DotEndpoint() + " / DoH " + t.DoHEndpoint(),
			"dig_dot":             "dig @127.0.0.1 -p 853 " + t.DotEndpoint() + " +tls example.com A",
			"curl_doh":            "curl -H 'accept: application/dns-message' -H 'content-type: application/dns-message' --data-binary @query.bin " + t.DoHEndpoint(),
		},
		"nginx_snippet": nginxSnippet(t),
		"caddy_snippet": caddySnippet(t),
	}
	writeJSON(w, http.StatusOK, ep)
}

func nginxSnippet(t *model.Tenant) string {
	return `# DoH upstream for prefix ` + t.Prefix + `
location / {
    proxy_pass http://127.0.0.1:8443;
    proxy_set_header Host ` + t.DotEndpoint() + `;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 10s;
}`
}

func caddySnippet(t *model.Tenant) string {
	return t.DotEndpoint() + ` {
    tls {
        protocols tls1.2 tls1.3
    }
    handle /dns-query {
        reverse_proxy 127.0.0.1:8443
    }
}`
}

// warmTenant pre-warms the tenant's hot domains across all active ECS
// subnets (通过 ECS 对已缓存数据动态预热).
func (a *API) warmTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	t, err := a.repos.GetTenant(r.Context(), id)
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	hots, err := a.repos.ListHotDomains(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var domains []string
	for _, h := range hots {
		if h.Enabled && (h.TenantID == "" || h.TenantID == t.ID) {
			domains = append(domains, h.Domain)
		}
	}
	if len(domains) == 0 {
		writeErr(w, http.StatusBadRequest, "no hot domains configured for this tenant")
		return
	}
	job, err := a.core.Warmup().Warm(r.Context(), t.ID, domains, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAction(r, "cache.warm", "tenant:"+t.ID, map[string]any{"job": job.ID, "domains": len(domains), "ecs": len(job.ECSs)})
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) tenantStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c := claimsFrom(r)
	if c.Role == string(model.RoleTenant) {
		// tenant users see only their own
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": id,
		"queries":   a.core.TenantQueries(id),
	})
}

// bootstrapAdmin creates the initial platform admin. Requires the
// X-Bootstrap-Token header matching BOOTSTRAP_TOKEN; works only once (it is
// disabled as soon as any admin account exists).
func (a *API) bootstrapAdmin(w http.ResponseWriter, r *http.Request) {
	if a.cfg.BootstrapToken == "" {
		writeErr(w, http.StatusForbidden, "bootstrap disabled: set BOOTSTRAP_TOKEN env")
		return
	}
	if r.Header.Get("X-Bootstrap-Token") != a.cfg.BootstrapToken {
		writeErr(w, http.StatusUnauthorized, "invalid bootstrap token")
		return
	}
	existing, err := a.repos.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, u := range existing {
		if u.Role == model.RoleAdmin {
			writeErr(w, http.StatusConflict, "admin already exists — bootstrap disabled")
			return
		}
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if in.Username == "" || len(in.Password) < 12 {
		writeErr(w, http.StatusBadRequest, "username required; password >= 12 chars")
		return
	}
	u := &model.User{
		ID:       uuid.NewString(),
		Username: strings.ToLower(in.Username),
		Role:     model.RoleAdmin,
		Email:    in.Email,
	}
	if err := a.repos.CreateUser(r.Context(), u, in.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.mysql.WriteAudit(r.Context(), model.AuditRow{
		ActorName: "bootstrap",
		Action:    "auth.bootstrap_admin",
		Target:    "user:" + u.Username,
		ClientIP:  clientIP(r),
	})
	writeJSON(w, http.StatusCreated, map[string]string{"status": "admin created", "username": u.Username})
}

// --- users ---

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	us, err := a.repos.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, us)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TenantID string `json:"tenant_id"`
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Email    string `json:"email"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if in.Username == "" || len(in.Password) < 12 {
		writeErr(w, http.StatusBadRequest, "username required; password >= 12 chars")
		return
	}
	role := model.Role(in.Role)
	if role != model.RoleAdmin && role != model.RoleTenant {
		role = model.RoleTenant
	}
	u := &model.User{
		ID:       uuid.NewString(),
		TenantID: in.TenantID,
		Username: strings.ToLower(in.Username),
		Role:     role,
		Email:    in.Email,
	}
	if err := a.repos.CreateUser(r.Context(), u, in.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	u.PasswordHash = ""
	a.auditAction(r, "user.create", "user:"+u.Username, "")
	writeJSON(w, http.StatusCreated, u)
}

func (a *API) setPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(in.Password) < 12 {
		writeErr(w, http.StatusBadRequest, "password must be >= 12 chars")
		return
	}
	if err := a.repos.SetPassword(r.Context(), r.PathValue("id"), in.Password); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAction(r, "user.password_reset", "user:"+r.PathValue("id"), "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// updateUser edits a user's role, tenant binding and email (admin only).
func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Role     string `json:"role"`
		TenantID string `json:"tenant_id"`
		Email    string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := a.repos.GetUserByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	role := string(u.Role)
	if in.Role != "" {
		if in.Role != string(model.RoleAdmin) && in.Role != string(model.RoleTenant) {
			writeErr(w, http.StatusBadRequest, "invalid role")
			return
		}
		role = in.Role
	}
	tenantID := u.TenantID
	if in.TenantID != "" {
		tenantID = in.TenantID
	}
	if role == string(model.RoleTenant) && tenantID == "" {
		writeErr(w, http.StatusBadRequest, "tenant user must be bound to a tenant")
		return
	}
	if err := a.repos.UpdateUser(r.Context(), id, role, tenantID, in.Email); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAction(r, "user.update", "user:"+id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := a.repos.GetUserByID(r.Context(), id); err != nil || id == "" {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	// no self-delete
	c := claimsFrom(r)
	if c.Subject == id {
		writeErr(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}
	a.auditAction(r, "user.delete", "user:"+id, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- helpers ---

func (a *API) auditAction(r *http.Request, action, target string, detail any) {
	c := claimsFrom(r)
	actorID, name := "", "unknown"
	if c != nil {
		actorID = c.Subject
		if u, err := a.repos.GetUserByID(r.Context(), c.Subject); err == nil && u != nil {
			name = u.Username
		}
	}
	_ = a.mysql.WriteAudit(r.Context(), model.AuditRow{
		ActorID:   actorID,
		ActorName: name,
		Action:    action,
		Target:    target,
		Detail:    jsonDetail(detail),
		ClientIP:  clientIP(r),
	})
}

func jsonDetail(v any) string {
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// randomPassword generates a strong temporary password (for auto-created
// tenant admin accounts).
func randomPassword() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	b := make([]byte, 18)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}
