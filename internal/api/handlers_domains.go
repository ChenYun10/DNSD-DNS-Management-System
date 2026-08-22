// Tenant custom main domains (客户自定义主域名) + admin-managed SSL (后台做SSL).
//
// A tenant binds one of its own domains; DNS queries matching the domain (or
// any subdomain) route to the tenant, and the backend issues/renews the
// domain's TLS certificate via ACME (HTTP-01 behind nginx, or Aliyun DNS-01).
package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"dns-platform/internal/certmgr"
	"dns-platform/internal/model"
)

// getCertMgr returns the ACME manager; nil when disabled.
func (a *API) getCertMgr() *certmgr.Manager {
	return a.certs
}

// listDomains GET /api/v1/domains?tenant_id= — all domains (admin) or scoped.
func (a *API) listDomains(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")
	// tenant role is forced into its own tenant scope
	if c := claimsFrom(r); c != nil && c.Role == string(model.RoleTenant) {
		tenantID = c.TID
	}
	domains, err := a.repos.ListTenantDomains(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": domains})
}

type createDomainReq struct {
	TenantID string `json:"tenant_id"`
	Domain   string `json:"domain"`
}

// createDomain POST /api/v1/domains — bind a customer main domain to a tenant.
func (a *API) createDomain(w http.ResponseWriter, r *http.Request) {
	var req createDomainReq
	if err := readJSON(w, r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(req.Domain, ".")))
	if req.Domain == "" || !strings.Contains(req.Domain, ".") || strings.Contains(req.Domain, " ") {
		writeErr(w, http.StatusBadRequest, "valid domain required (e.g. dns.customer.com)")
		return
	}
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	t, err := a.repos.GetTenant(r.Context(), req.TenantID)
	if err != nil || t == nil {
		writeErr(w, http.StatusNotFound, "tenant not found")
		return
	}
	base := strings.ToLower(strings.TrimSuffix(a.cfg.BaseDomain, "."))
	if req.Domain == base || strings.HasSuffix(req.Domain, "."+base) {
		writeErr(w, http.StatusBadRequest, "domain overlaps the platform base domain")
		return
	}
	td := &model.TenantDomain{
		ID:         uuid.NewString(),
		TenantID:   req.TenantID,
		Domain:     req.Domain,
		CertStatus: model.CertNone,
	}
	if err := a.repos.CreateTenantDomain(r.Context(), td); err != nil {
		if strings.Contains(err.Error(), "Duplicate") {
			writeErr(w, http.StatusConflict, "domain already bound")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.bumpConfig(r.Context())
	a.auditAction(r, "domain.create", req.Domain, req.TenantID)
	writeJSON(w, http.StatusCreated, td)
}

// deleteDomain DELETE /api/v1/domains/{id}
func (a *API) deleteDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	td, err := a.repos.GetTenantDomain(r.Context(), id)
	if err != nil || td == nil {
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	if err := a.repos.DeleteTenantDomain(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.bumpConfig(r.Context())
	a.auditAction(r, "domain.delete", td.Domain, td.TenantID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// issueDomainCert POST /api/v1/domains/{id}/issue?method=http01|dns01
func (a *API) issueDomainCert(w http.ResponseWriter, r *http.Request) {
	mgr := a.getCertMgr()
	if mgr == nil || !a.cfg.ACMEEnabled {
		writeErr(w, http.StatusServiceUnavailable, "ACME disabled (set ACME_ENABLED=true + ACME_EMAIL)")
		return
	}
	id := r.PathValue("id")
	td, err := a.repos.GetTenantDomain(r.Context(), id)
	if err != nil || td == nil {
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	method := r.URL.Query().Get("method")
	if method == "" {
		method = "http01"
	}
	if method != "http01" && method != "dns01" {
		writeErr(w, http.StatusBadRequest, "method must be http01 or dns01")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	if err := mgr.Issue(ctx, td, method); err != nil {
		writeErr(w, http.StatusBadGateway, "issue failed: "+err.Error())
		return
	}
	a.auditAction(r, "domain.cert_issue", td.Domain, td.TenantID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "issued"})
}

// certsOverview GET /api/v1/certs — base wildcard + tenant domains status.
func (a *API) certsOverview(w http.ResponseWriter, r *http.Request) {
	base := struct {
		Domain string     `json:"domain"`
		Expiry *time.Time `json:"expiry,omitempty"`
		Valid  bool       `json:"valid"`
		Source string     `json:"source"`
	}{Domain: a.cfg.BaseDomain, Source: "acme.sh"}
	if exp, err := certExpiryFromFile(a.cfg.TLSCertFile); err == nil {
		base.Expiry = &exp
		base.Valid = time.Until(exp) > 0
	}
	domains, err := a.repos.ListTenantDomains(r.Context(), "")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// refresh on-disk expiry if DB says active
	for _, td := range domains {
		if td.CertStatus == model.CertActive && td.CertExpiry == nil {
			if mgr := a.getCertMgr(); mgr != nil {
				if exp, err := mgr.DomainCertExpiry(td.Domain); err == nil {
					td.CertExpiry = &exp
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"acme_enabled": a.cfg.ACMEEnabled,
		"acme_staging": a.cfg.ACMEStaging,
		"base":         base,
		"domains":      domains,
	})
}

func certExpiryFromFile(certFile string) (time.Time, error) {
	return certmgr.CertExpiryFromFile(certFile)
}
