// Package store: tenant custom-domain repositories (customer main domains).
//
// A tenant can bind one or more of its own domains (主域名) instead of (or in
// addition to) a <prefix>.<base_domain> endpoint. DNS queries whose SNI/Host
// matches a bound domain — or any subdomain of it — route to that tenant, and
// the platform issues/renews the domain's TLS certificate automatically.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"dns-platform/internal/model"
)

var tenantDomainCols = "id, tenant_id, domain, enabled, cert_status, cert_expiry, cert_error, created_at, updated_at"

func scanTenantDomain(row *sql.Row) (*model.TenantDomain, error) {
	var td model.TenantDomain
	var enabled int
	var expiry sql.NullTime
	var errMsg sql.NullString
	if err := row.Scan(&td.ID, &td.TenantID, &td.Domain, &enabled,
		&td.CertStatus, &expiry, &errMsg, &td.CreatedAt, &td.UpdatedAt); err != nil {
		return nil, err
	}
	td.Enabled = enabled == 1
	if expiry.Valid {
		e := expiry.Time
		td.CertExpiry = &e
	}
	if errMsg.Valid {
		td.CertError = errMsg.String
	}
	return &td, nil
}

// TenantByDomain resolves the tenant owning host (exact match or any
// subdomain of a bound domain; most specific binding wins). Returns nil,nil
// when no tenant claims the name. Results are cached in Redis for 5m and
// purged together with the rest of the meta cache on reload.
func (r *Repos) TenantByDomain(ctx context.Context, host string) (*model.Tenant, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, nil
	}
	cacheKey := "dns:meta:domain:" + Safe(host)
	if raw, err := r.rdb.Get(ctx, cacheKey).Result(); err == nil {
		var t model.Tenant
		if json.Unmarshal([]byte(raw), &t) == nil {
			return &t, nil
		}
	}
	q := `SELECT ` + tenantCols + ` FROM tenants t
	      JOIN tenant_domains td ON td.tenant_id = t.id
	      WHERE td.enabled = 1 AND (? = td.domain OR ? LIKE CONCAT('%.', td.domain))
	      ORDER BY LENGTH(td.domain) DESC LIMIT 1`
	row := r.db.QueryRowContext(ctx, q, host, host)
	t, err := scanTenant(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if b, err := json.Marshal(t); err == nil {
		r.rdb.Set(ctx, cacheKey, b, 5*time.Minute)
	}
	return t, nil
}

func (r *Repos) ListTenantDomains(ctx context.Context, tenantID string) ([]*model.TenantDomain, error) {
	q := "SELECT " + tenantDomainCols + " FROM tenant_domains"
	var args []any
	if tenantID != "" {
		q += " WHERE tenant_id = ?"
		args = append(args, tenantID)
	}
	q += " ORDER BY created_at DESC"
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.TenantDomain{}
	for rows.Next() {
		var td model.TenantDomain
		var enabled int
		var expiry sql.NullTime
		var errMsg sql.NullString
		if err := rows.Scan(&td.ID, &td.TenantID, &td.Domain, &enabled,
			&td.CertStatus, &expiry, &errMsg, &td.CreatedAt, &td.UpdatedAt); err != nil {
			return nil, err
		}
		td.Enabled = enabled == 1
		if expiry.Valid {
			e := expiry.Time
			td.CertExpiry = &e
		}
		if errMsg.Valid {
			td.CertError = errMsg.String
		}
		out = append(out, &td)
	}
	return out, rows.Err()
}

func (r *Repos) GetTenantDomain(ctx context.Context, id string) (*model.TenantDomain, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+tenantDomainCols+" FROM tenant_domains WHERE id = ?", id)
	return scanTenantDomain(row)
}

func (r *Repos) CreateTenantDomain(ctx context.Context, td *model.TenantDomain) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tenant_domains (id, tenant_id, domain, enabled, cert_status)
		 VALUES (?, ?, ?, 1, 'none')`,
		td.ID, td.TenantID, strings.ToLower(strings.TrimSuffix(td.Domain, ".")))
	return err
}

func (r *Repos) DeleteTenantDomain(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM tenant_domains WHERE id = ?", id)
	return err
}

func (r *Repos) SetDomainCert(ctx context.Context, id string, status model.CertStatus, expiry *time.Time, errMsg string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE tenant_domains SET cert_status = ?, cert_expiry = ?, cert_error = ? WHERE id = ?`,
		status, expiry, errMsg, id)
	return err
}
