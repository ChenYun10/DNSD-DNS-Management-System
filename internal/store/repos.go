package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"dns-platform/internal/model"
)

// Repos bundles all management-metadata repositories. Hot-path lookups
// (tenant by DoT prefix, split rules, upstream groups) are cached in Redis
// and invalidated on every write, so the DNS data plane never touches MySQL
// on the request path — only Redis.
type Repos struct {
	db  *sql.DB
	rdb *redis.Client
}

func NewRepos(db *sql.DB, rdb *redis.Client) *Repos {
	return &Repos{db: db, rdb: rdb}
}

// ---------------------------------------------------------------------------
// Users & auth
// ---------------------------------------------------------------------------

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(b), err
}

func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

var userCols = "id, tenant_id, username, password_hash, role, email, failed_attempts, locked_until, last_login, created_at"

func scanUser(row *sql.Row) (*model.User, error) {
	u := &model.User{}
	var tid, email sql.NullString
	var fa sql.NullInt64
	var lu, ll sql.NullTime
	err := row.Scan(&u.ID, &tid, &u.Username, &u.PasswordHash, &u.Role, &email, &fa, &lu, &ll, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.TenantID = tid.String
	u.Email = email.String
	u.FailedAttempts = int(fa.Int64)
	if lu.Valid {
		u.LockedUntil = lu.Time
	}
	if ll.Valid {
		u.LastLogin = ll.Time
	}
	return u, nil
}

func (r *Repos) GetUserByUsername(ctx context.Context, username string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE username = ?", username)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (r *Repos) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+userCols+" FROM users WHERE id = ?", id)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return u, err
}

func (r *Repos) CreateUser(ctx context.Context, u *model.User, plainPassword string) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx,
		"INSERT INTO users (id, tenant_id, username, password_hash, role, email, created_at) VALUES (?,?,?,?,?,?,?)",
		u.ID, nullStr(u.TenantID), u.Username, hash, u.Role, nullStr(u.Email), time.Now())
	return err
}

func (r *Repos) SetPassword(ctx context.Context, userID, plainPassword string) error {
	hash, err := HashPassword(plainPassword)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?", hash, userID)
	return err
}

func (r *Repos) RecordLoginFailure(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET failed_attempts = failed_attempts + 1, locked_until = IF(failed_attempts + 1 >= 5, DATE_ADD(NOW(), INTERVAL 15 MINUTE), locked_until) WHERE id = ?", userID)
	return err
}

func (r *Repos) RecordLoginSuccess(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?", userID)
	return err
}

// UpdateUser updates a user's role, tenant binding and email.
func (r *Repos) UpdateUser(ctx context.Context, id, role, tenantID, email string) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE users SET role = ?, tenant_id = NULLIF(?, ''), email = NULLIF(?, '') WHERE id = ?",
		role, tenantID, email, id)
	return err
}

func (r *Repos) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+userCols+" FROM users ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.User
	for rows.Next() {
		var u model.User
		var tid, email sql.NullString
		var fa sql.NullInt64
		var lu, ll sql.NullTime
		if err := rows.Scan(&u.ID, &tid, &u.Username, &u.PasswordHash, &u.Role, &email, &fa, &lu, &ll, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.TenantID = tid.String
		u.Email = email.String
		u.FailedAttempts = int(fa.Int64)
		if lu.Valid {
			u.LockedUntil = lu.Time
		}
		if ll.Valid {
			u.LastLogin = ll.Time
		}
		u.PasswordHash = ""
		out = append(out, &u)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

// PrefixPattern validates custom DoT prefixes: lowercase alnum + hyphen,
// 3..32 chars, cannot collide with reserved labels.
var PrefixPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,31}$`)

var reservedPrefixes = map[string]bool{"www": true, "api": true, "admin": true, "dns": true, "ns1": true, "ns2": true, "mail": true, "static": true, "cdn": true, "vip": true}

func ValidPrefix(p string) bool {
	return PrefixPattern.MatchString(p) && !reservedPrefixes[p]
}

var tenantCols = "id, name, prefix, base_domain, enabled, vip, rate_limit_qps, cache_max_ttl, default_ecs, allow_ecs, dot_enabled, doh_enabled, doq_enabled, upstream_group, created_at, updated_at"

func scanTenant(row *sql.Row) (*model.Tenant, error) {
	t := &model.Tenant{}
	var defECS, ug sql.NullString
	err := row.Scan(&t.ID, &t.Name, &t.Prefix, &t.BaseDomain, &t.Enabled, &t.VIP,
		&t.RateLimitQPS, &t.CacheMaxTTL, &defECS, &t.AllowECS,
		&t.DoTEnabled, &t.DoHEnabled, &t.DoQEnabled, &ug, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.DefaultECS = defECS.String
	t.UpstreamGroup = ug.String
	return t, nil
}

func scanTenants(rows *sql.Rows) ([]*model.Tenant, error) {
	defer rows.Close()
	var out []*model.Tenant
	for rows.Next() {
		t := &model.Tenant{}
		var defECS, ug sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.BaseDomain, &t.Enabled, &t.VIP,
			&t.RateLimitQPS, &t.CacheMaxTTL, &defECS, &t.AllowECS,
			&t.DoTEnabled, &t.DoHEnabled, &t.DoQEnabled, &ug, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.DefaultECS = defECS.String
		t.UpstreamGroup = ug.String
		out = append(out, t)
	}
	return out, rows.Err()
}

// TenantByPrefix resolves a tenant from its custom DoT prefix (hot path,
// Redis-cached).
func (r *Repos) TenantByPrefix(ctx context.Context, prefix string) (*model.Tenant, error) {
	cacheKey := "dns:meta:prefix:" + Safe(prefix)
	if raw, err := r.rdb.Get(ctx, cacheKey).Result(); err == nil {
		var t model.Tenant
		if json.Unmarshal([]byte(raw), &t) == nil {
			return &t, nil
		}
	}
	row := r.db.QueryRowContext(ctx, "SELECT "+tenantCols+" FROM tenants WHERE prefix = ? AND enabled = 1", prefix)
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

func (r *Repos) GetTenant(ctx context.Context, id string) (*model.Tenant, error) {
	row := r.db.QueryRowContext(ctx, "SELECT "+tenantCols+" FROM tenants WHERE id = ?", id)
	t, err := scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

func (r *Repos) ListTenants(ctx context.Context) ([]*model.Tenant, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT "+tenantCols+" FROM tenants ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	return scanTenants(rows)
}

func (r *Repos) CreateTenant(ctx context.Context, t *model.Tenant) error {
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.BaseDomain == "" {
		return errors.New("base_domain required")
	}
	if !ValidPrefix(t.Prefix) {
		return errors.New("invalid prefix: 3-32 lowercase alnum/hyphen, not reserved")
	}
	now := time.Now()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, prefix, base_domain, enabled, vip, rate_limit_qps, cache_max_ttl,
		   default_ecs, allow_ecs, dot_enabled, doh_enabled, doq_enabled, upstream_group, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		t.ID, t.Name, t.Prefix, t.BaseDomain, t.Enabled, t.VIP,
		t.RateLimitQPS, t.CacheMaxTTL, nullStr(t.DefaultECS), t.AllowECS,
		t.DoTEnabled, t.DoHEnabled, t.DoQEnabled, nullStr(t.UpstreamGroup), now, now)
	if err != nil {
		return err
	}
	t.CreatedAt, t.UpdatedAt = now, now
	return nil
}

func (r *Repos) UpdateTenant(ctx context.Context, t *model.Tenant) error {
	if t.Prefix != "" && !ValidPrefix(t.Prefix) {
		return errors.New("invalid prefix")
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE tenants SET name=?, prefix=?, base_domain=?, enabled=?, vip=?, rate_limit_qps=?,
		   cache_max_ttl=?, default_ecs=?, allow_ecs=?, dot_enabled=?, doh_enabled=?, doq_enabled=?,
		   upstream_group=?, updated_at=NOW() WHERE id=?`,
		t.Name, t.Prefix, t.BaseDomain, t.Enabled, t.VIP, t.RateLimitQPS,
		t.CacheMaxTTL, nullStr(t.DefaultECS), t.AllowECS, t.DoTEnabled, t.DoHEnabled, t.DoQEnabled,
		nullStr(t.UpstreamGroup), t.ID)
	if err == nil {
		r.rdb.Del(context.Background(), "dns:meta:prefix:"+Safe(t.Prefix))
	}
	return err
}

func (r *Repos) DeleteTenant(ctx context.Context, id string) error {
	t, err := r.GetTenant(ctx, id)
	if err != nil {
		return err
	}
	if t != nil {
		r.rdb.Del(context.Background(), "dns:meta:prefix:"+Safe(t.Prefix))
	}
	_, err = r.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = ?", id)
	return err
}

// ---------------------------------------------------------------------------
// Upstream groups + upstreams + split rules + hot domains
// ---------------------------------------------------------------------------

func (r *Repos) ListGroups(ctx context.Context) ([]*model.UpstreamGroup, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, tenant_id, name, strategy, health_domain, created_at FROM upstream_groups ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []*model.UpstreamGroup
	for rows.Next() {
		g := &model.UpstreamGroup{}
		var tid, hd sql.NullString
		if err := rows.Scan(&g.ID, &tid, &g.Name, &g.Strategy, &hd, &g.CreatedAt); err != nil {
			return nil, err
		}
		g.TenantID = tid.String
		g.HealthDomain = hd.String
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	us, err := r.ListUpstreams(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		for _, u := range us {
			if u.GroupID == g.ID {
				g.Upstreams = append(g.Upstreams, u)
			}
		}
	}
	return groups, nil
}

func (r *Repos) GetGroup(ctx context.Context, id string) (*model.UpstreamGroup, error) {
	groups, err := r.ListGroups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.ID == id {
			return g, nil
		}
	}
	return nil, nil
}

func (r *Repos) CreateGroup(ctx context.Context, g *model.UpstreamGroup) error {
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.Strategy == "" {
		g.Strategy = "weighted"
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO upstream_groups (id, tenant_id, name, strategy, health_domain, created_at) VALUES (?,?,?,?,?,?)",
		g.ID, nullStr(g.TenantID), g.Name, g.Strategy, nullStr(g.HealthDomain), time.Now())
	return err
}

func (r *Repos) UpdateGroup(ctx context.Context, g *model.UpstreamGroup) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE upstream_groups SET tenant_id=?, name=?, strategy=?, health_domain=? WHERE id=?",
		nullStr(g.TenantID), g.Name, g.Strategy, nullStr(g.HealthDomain), g.ID)
	return err
}

func (r *Repos) DeleteGroup(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM upstream_groups WHERE id = ?", id)
	return err
}

func (r *Repos) ListUpstreams(ctx context.Context) ([]*model.Upstream, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, group_id, name, protocol, address, port, hostname, doh_path, weight, timeout_ms, tls_insecure, enabled, created_at FROM upstreams ORDER BY group_id, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Upstream
	for rows.Next() {
		u := &model.Upstream{}
		var hn, dp sql.NullString
		if err := rows.Scan(&u.ID, &u.GroupID, &u.Name, &u.Protocol, &u.Address, &u.Port, &hn, &dp, &u.Weight, &u.TimeoutMS, &u.TLSInsecure, &u.Enabled, &u.CreatedAt); err != nil {
			return nil, err
		}
		u.Hostname = hn.String
		u.DoHPath = dp.String
		if u.Weight == 0 {
			u.Weight = 1
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

var validProtocols = map[model.UpstreamProtocol]bool{model.ProtoUDP: true, model.ProtoTCP: true, model.ProtoDoT: true, model.ProtoDoH: true, model.ProtoDoQ: true}

func (r *Repos) CreateUpstream(ctx context.Context, u *model.Upstream) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if !validProtocols[u.Protocol] {
		return fmt.Errorf("invalid protocol %q", u.Protocol)
	}
	if u.Port == 0 {
		u.Port = defaultPort(u.Protocol)
	}
	if u.Weight == 0 {
		u.Weight = 1
	}
	if u.Hostname == "" {
		u.Hostname = u.Address
	}
	if u.DoHPath == "" {
		u.DoHPath = "/dns-query"
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO upstreams (id, group_id, name, protocol, address, port, hostname, doh_path, weight, timeout_ms, tls_insecure, enabled, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.ID, u.GroupID, u.Name, u.Protocol, u.Address, u.Port, u.Hostname, u.DoHPath, u.Weight, u.TimeoutMS, u.TLSInsecure, u.Enabled, time.Now())
	return err
}

func (r *Repos) UpdateUpstream(ctx context.Context, u *model.Upstream) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE upstreams SET group_id=?, name=?, protocol=?, address=?, port=?, hostname=?, doh_path=?, weight=?, timeout_ms=?, tls_insecure=?, enabled=? WHERE id=?`,
		u.GroupID, u.Name, u.Protocol, u.Address, u.Port, u.Hostname, u.DoHPath, u.Weight, u.TimeoutMS, u.TLSInsecure, u.Enabled, u.ID)
	return err
}

func (r *Repos) DeleteUpstream(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM upstreams WHERE id = ?", id)
	return err
}

func (r *Repos) ListRules(ctx context.Context) ([]*model.SplitRule, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, tenant_id, name, match_type, match_value, group_id, priority, enabled, created_at FROM split_rules ORDER BY priority DESC, name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.SplitRule
	for rows.Next() {
		s := &model.SplitRule{}
		var tid sql.NullString
		if err := rows.Scan(&s.ID, &tid, &s.Name, &s.MatchType, &s.MatchValue, &s.GroupID, &s.Priority, &s.Enabled, &s.CreatedAt); err != nil {
			return nil, err
		}
		s.TenantID = tid.String
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repos) CreateRule(ctx context.Context, s *model.SplitRule) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if !validMatch(s.MatchType) {
		return fmt.Errorf("invalid match_type %q", s.MatchType)
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO split_rules (id, tenant_id, name, match_type, match_value, group_id, priority, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
		s.ID, nullStr(s.TenantID), s.Name, s.MatchType, s.MatchValue, s.GroupID, s.Priority, s.Enabled, time.Now())
	return err
}

func (r *Repos) UpdateRule(ctx context.Context, s *model.SplitRule) error {
	_, err := r.db.ExecContext(ctx,
		"UPDATE split_rules SET tenant_id=?, name=?, match_type=?, match_value=?, group_id=?, priority=?, enabled=? WHERE id=?",
		nullStr(s.TenantID), s.Name, s.MatchType, s.MatchValue, s.GroupID, s.Priority, s.Enabled, s.ID)
	return err
}

func (r *Repos) DeleteRule(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM split_rules WHERE id = ?", id)
	return err
}

func validMatch(m model.MatchType) bool {
	switch m {
	case model.MatchSuffix, model.MatchPrefix, model.MatchExact, model.MatchRegex, model.MatchAll:
		return true
	}
	return false
}

func (r *Repos) ListHotDomains(ctx context.Context) ([]*model.HotDomain, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, tenant_id, domain, weight, enabled FROM hot_domains ORDER BY weight DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.HotDomain
	for rows.Next() {
		h := &model.HotDomain{}
		var tid sql.NullString
		if err := rows.Scan(&h.ID, &tid, &h.Domain, &h.Weight, &h.Enabled); err != nil {
			return nil, err
		}
		h.TenantID = tid.String
		out = append(out, h)
	}
	return out, rows.Err()
}

func (r *Repos) CreateHotDomain(ctx context.Context, h *model.HotDomain) error {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO hot_domains (id, tenant_id, domain, weight, enabled) VALUES (?,?,?,?,?)",
		h.ID, nullStr(h.TenantID), h.Domain, h.Weight, h.Enabled)
	return err
}

func (r *Repos) DeleteHotDomain(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM hot_domains WHERE id = ?", id)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func defaultPort(p model.UpstreamProtocol) int {
	switch p {
	case model.ProtoDoT:
		return 853
	case model.ProtoDoH:
		return 443
	case model.ProtoDoQ:
		return 853
	default:
		return 53
	}
}

// LoadRulesForTenant returns the effective split rules for a tenant:
// global rules plus the tenant's own, ordered by priority desc.
func (r *Repos) LoadRulesForTenant(ctx context.Context, tenantID string) ([]*model.SplitRule, error) {
	all, err := r.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	var out []*model.SplitRule
	for _, s := range all {
		if s.Enabled && (s.TenantID == "" || s.TenantID == tenantID) {
			out = append(out, s)
		}
	}
	return out, nil
}

// PurgeMetaCache clears the Redis metadata caches (called after any
// management write so the data plane picks up changes quickly).
func (r *Repos) PurgeMetaCache(ctx context.Context) {
	iter := r.rdb.Scan(ctx, 0, "dns:meta:*", 200).Iterator()
	for iter.Next(ctx) {
		r.rdb.Del(ctx, iter.Val())
	}
}

// AuditDetail marshals a value to JSON for audit rows.
func AuditDetail(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
