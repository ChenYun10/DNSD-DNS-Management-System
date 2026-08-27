// Package api implements the REST control plane (JWT + RBAC), fully isolated
// from the DNS data plane:
//
//	DNS daemon (dnsd):     :53/:853/:8443/:784  — never touches MySQL
//	API daemon (apid):     :8080 (customer) + :8443 (admin, optional mTLS)
//	Frontend:              static SPA, separate origin, talks only to apid
//
// All SQL is parameterized, all inputs are validated, all admin actions are
// audit-logged. Tenant users are scoped to their own tenant (RBAC).
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/dnsx"
	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

type API struct {
	cfg     *config.Config
	repos   *store.Repos
	mysql   *store.MySQLStore
	logger  *store.QueryLogWriter
	core    *dnsx.Core
	rdb     *redis.Client
	limiter *dnsx.Limiter
	auth    *Auth
}

func New(cfg *config.Config, repos *store.Repos, mysql *store.MySQLStore, logger *store.QueryLogWriter, core *dnsx.Core, rdb *redis.Client) *API {
	a := &API{cfg: cfg, repos: repos, mysql: mysql, logger: logger, core: core, rdb: rdb}
	a.limiter = dnsx.NewLimiter(rdb, cfg.RateLimitQPS, cfg.RateLimitVIPMult)
	a.auth = NewAuth(cfg, repos, mysql, rdb, a.limiter)
	return a
}

// Handler builds the router with all middleware.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	// public
	mux.HandleFunc("GET /api/v1/healthz", a.healthz)
	mux.HandleFunc("GET /api/v1/readyz", a.readyz)
	mux.HandleFunc("GET /api/v1/system/info", a.systemInfo)
	mux.HandleFunc("POST /api/v1/auth/login", a.auth.login)
	mux.HandleFunc("POST /api/v1/auth/refresh", a.auth.refresh)
	mux.HandleFunc("POST /api/v1/bootstrap/admin", a.bootstrapAdmin)

	// authenticated
	mux.HandleFunc("POST /api/v1/auth/logout", a.chain(a.auth.logout, a.auth.authMiddleware))
	mux.HandleFunc("POST /api/v1/auth/change-password", a.chain(a.auth.changePassword, a.auth.authMiddleware))
	mux.HandleFunc("GET /api/v1/me", a.chain(a.me, a.auth.authMiddleware))

	// ------------------------------------------------------------------
	// 三员分立(等保三级): sysadmin 系统管理 / secadmin 安全管理 / auditadmin 审计管理
	// admin(旧超管)由 requireRole 内部兼容为 sysadmin
	// ------------------------------------------------------------------

	// tenants: 系统管理员(sysadmin)
	mux.HandleFunc("GET /api/v1/tenants", a.chain(a.listTenants, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/tenants", a.chain(a.createTenant, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("GET /api/v1/tenants/{id}", a.chain(a.getTenant, a.auth.authMiddleware, a.scopeTenant))
	mux.HandleFunc("PUT /api/v1/tenants/{id}", a.chain(a.updateTenant, a.auth.authMiddleware, a.scopeTenant))
	mux.HandleFunc("DELETE /api/v1/tenants/{id}", a.chain(a.deleteTenant, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/tenants/{id}/dot", a.chain(a.customizeDot, a.auth.authMiddleware, a.scopeTenant))
	mux.HandleFunc("GET /api/v1/tenants/{id}/endpoints", a.chain(a.tenantEndpoints, a.auth.authMiddleware, a.scopeTenant))
	mux.HandleFunc("POST /api/v1/tenants/{id}/warm", a.chain(a.warmTenant, a.auth.authMiddleware, a.scopeTenant))
	mux.HandleFunc("GET /api/v1/tenants/{id}/stats", a.chain(a.tenantStats, a.auth.authMiddleware, a.scopeTenant))

	// users: 系统管理员(账号生命周期归 sysadmin; 锁定/强制下线归 secadmin)
	mux.HandleFunc("GET /api/v1/users", a.chain(a.listUsers, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/users", a.chain(a.createUser, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("PUT /api/v1/users/{id}", a.chain(a.updateUser, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/users/{id}/password", a.chain(a.setPassword, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.chain(a.deleteUser, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))

	// security: 安全管理员(secadmin) — 账号锁定/解锁/强制下线/安全概览
	mux.HandleFunc("POST /api/v1/security/users/{id}/lock", a.chain(a.secLockUser, a.auth.authMiddleware, requireRole(model.RoleSecAdmin)))
	mux.HandleFunc("POST /api/v1/security/users/{id}/unlock", a.chain(a.secUnlockUser, a.auth.authMiddleware, requireRole(model.RoleSecAdmin)))
	mux.HandleFunc("POST /api/v1/security/users/{id}/revoke-sessions", a.chain(a.secRevokeSessions, a.auth.authMiddleware, requireRole(model.RoleSecAdmin)))
	mux.HandleFunc("GET /api/v1/security/overview", a.chain(a.secOverview, a.auth.authMiddleware, requireRole(model.RoleSecAdmin)))

	// upstreams / groups / split rules: 系统管理员(sysadmin)
	mux.HandleFunc("GET /api/v1/groups", a.chain(a.listGroups, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/groups", a.chain(a.createGroup, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("PUT /api/v1/groups/{id}", a.chain(a.updateGroup, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", a.chain(a.deleteGroup, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/upstreams", a.chain(a.createUpstream, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("PUT /api/v1/upstreams/{id}", a.chain(a.updateUpstream, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("DELETE /api/v1/upstreams/{id}", a.chain(a.deleteUpstream, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("GET /api/v1/rules", a.chain(a.listRules, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/rules", a.chain(a.createRule, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("PUT /api/v1/rules/{id}", a.chain(a.updateRule, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("DELETE /api/v1/rules/{id}", a.chain(a.deleteRule, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/reload", a.chain(a.reload, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))

	// hot domains: 系统管理员(sysadmin)
	mux.HandleFunc("GET /api/v1/hot-domains", a.chain(a.listHotDomains, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/hot-domains", a.chain(a.createHotDomain, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("DELETE /api/v1/hot-domains/{id}", a.chain(a.deleteHotDomain, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))

	// cache management: 系统管理员(sysadmin)
	mux.HandleFunc("GET /api/v1/cache/stats", a.chain(a.cacheStats, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/cache/purge", a.chain(a.cachePurge, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("POST /api/v1/cache/warm", a.chain(a.cacheWarm, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))
	mux.HandleFunc("GET /api/v1/cache/warm-jobs", a.chain(a.warmJobs, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))

	// ECS simulation (authenticated)
	mux.HandleFunc("POST /api/v1/dns/simulate", a.chain(a.simulate, a.auth.authMiddleware))

	// logs: query(租户可看自己) / audit(仅审计管理员 auditadmin)
	mux.HandleFunc("GET /api/v1/logs/query", a.chain(a.queryLogs, a.auth.authMiddleware))
	// 审计日志: GitHub 开源版三权分立(auditadmin 专属);
	// 服务器运营模式(ADMIN_FULL_AUDIT=true)下 admin 也可全量查看(运维需求)
	if a.cfg.AdminFullAudit {
		mux.HandleFunc("GET /api/v1/logs/audit", a.chain(a.queryAudit, a.auth.authMiddleware, requireRole(model.RoleAuditAdmin, model.RoleAdmin)))
		mux.HandleFunc("GET /api/v1/logs/audit/verify", a.chain(a.verifyAuditChain, a.auth.authMiddleware, requireRole(model.RoleAuditAdmin, model.RoleAdmin)))
	} else {
		mux.HandleFunc("GET /api/v1/logs/audit", a.chain(a.queryAudit, a.auth.authMiddleware, requireRole(model.RoleAuditAdmin)))
		mux.HandleFunc("GET /api/v1/logs/audit/verify", a.chain(a.verifyAuditChain, a.auth.authMiddleware, requireRole(model.RoleAuditAdmin)))
	}

	// stats
	mux.HandleFunc("GET /api/v1/stats/overview", a.chain(a.statsOverview, a.auth.authMiddleware))
	mux.HandleFunc("GET /api/v1/stats/upstreams", a.chain(a.statsUpstreams, a.auth.authMiddleware, requireRole(model.RoleSysAdmin)))

	return a.middleware(mux)
}


// Start binds the customer API and the dedicated admin channel
// (高价值专用通道: separate port, optional mTLS client certs).
func (a *API) Start() error {
	cust := &http.Server{
		Addr:              a.cfg.APIListen,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ln, err := net.Listen("tcp", a.cfg.APIListen)
	if err != nil {
		return fmt.Errorf("api listen %s: %w", a.cfg.APIListen, err)
	}
	go func() {
		if err := cust.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[api] customer channel: %v", err)
		}
	}()
	log.Printf("[api] customer API listening on %s", a.cfg.APIListen)

	// admin channel — separate port, optional mTLS
	adminLn, err := net.Listen("tcp", a.cfg.APIAdminListen)
	if err != nil {
		return fmt.Errorf("admin api listen %s: %w", a.cfg.APIAdminListen, err)
	}
	if a.cfg.APIMTLSCAFile != "" {
		caPEM, err := os.ReadFile(a.cfg.APIMTLSCAFile)
		if err != nil {
			return fmt.Errorf("mtls ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("mtls ca: no certificates parsed")
		}
		adminLn = tls.NewListener(adminLn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			Certificates: mustCert(a.cfg),
		})
		log.Printf("[api] admin channel (mTLS) listening on %s", a.cfg.APIAdminListen)
	} else {
		log.Printf("[api] admin channel listening on %s (no mTLS — set API_MTLS_CA_FILE in prod)", a.cfg.APIAdminListen)
	}
	adm := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		if err := adm.Serve(adminLn); err != nil && err != http.ErrServerClosed {
			log.Printf("[api] admin channel: %v", err)
		}
	}()
	return nil
}

func mustCert(cfg *config.Config) []tls.Certificate {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.Fatalf("load tls cert: %v", err)
	}
	return []tls.Certificate{cert}
}

// --- middleware ---

func (a *API) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// CORS: strict allowlist (前后端隔离: separate origins, no wildcard)
		origin := r.Header.Get("Origin")
		if origin != "" {
			for _, o := range a.cfg.APICORSOrigins {
				if strings.EqualFold(o, origin) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "false")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					w.Header().Set("Vary", "Origin")
					break
				}
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[api] panic: %v", rec)
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
		log.Printf("[api] %s %s %s %dms", clientIP(r), r.Method, r.URL.Path, time.Since(start).Milliseconds())
	})
}

func (a *API) chain(h http.HandlerFunc, mws ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// --- public endpoints ---

func (a *API) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	status := "ok"
	code := http.StatusOK
	if err := a.core.PingCache(ctx); err != nil {
		status = "cache_down: " + err.Error()
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]string{"status": status, "instance": a.cfg.InstanceID})
}

func (a *API) systemInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"base_domain": a.cfg.BaseDomain,
		"dnssec_mode": a.cfg.DNSSECMode,
		"ecs_enabled": a.cfg.ECSPassthrough,
		"version":     "1.0.0",
		"features":    []string{"udp", "tcp", "dot", "doh", "doq", "ecs", "dnssec", "redis-cache", "mysql-log", "warmup", "split"},
	})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	c := claimsFrom(r)
	u, err := a.repos.GetUserByID(r.Context(), c.Subject)
	if err != nil || u == nil {
		writeErr(w, http.StatusUnauthorized, "user not found")
		return
	}
	u.PasswordHash = ""
	out := map[string]any{"user": u}
	if u.TenantID != "" {
		if t, err := a.repos.GetTenant(r.Context(), u.TenantID); err == nil && t != nil {
			out["tenant"] = t
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- helpers ---

func clientIP(r *http.Request) string {
	if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
		return ip.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v)
}
