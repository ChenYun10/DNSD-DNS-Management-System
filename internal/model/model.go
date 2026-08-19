// Package model defines the shared domain types used across the DNS platform:
// tenants (multi-tenant DoT/DoH prefixes), users, upstreams, split rules,
// hot domains and log rows.
package model

import "time"

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleTenant Role = "tenant"
)

// Tenant is a customer workspace. Each tenant owns one or more custom
// DoT/DoH prefixes (e.g. "acme-01.dns.example.com"). VIP tenants get a
// reserved upstream pool, higher rate limits and the dedicated high-value
// channel.
type Tenant struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Prefix        string    `json:"prefix"` // custom DoT prefix (subdomain label)
	BaseDomain    string    `json:"base_domain"`
	Enabled       bool      `json:"enabled"`
	VIP           bool      `json:"vip"` // high-value government/enterprise channel
	RateLimitQPS  int       `json:"rate_limit_qps"`
	CacheMaxTTL   int       `json:"cache_max_ttl"` // seconds
	DefaultECS    string    `json:"default_ecs"`   // e.g. 203.0.113.0/24
	AllowECS      bool      `json:"allow_ecs"`     // accept client-supplied ECS
	DoTEnabled    bool      `json:"dot_enabled"`
	DoHEnabled    bool      `json:"doh_enabled"`
	DoQEnabled    bool      `json:"doq_enabled"`
	UpstreamGroup string    `json:"upstream_group"` // pinned group (VIP) or ""
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (t *Tenant) DotEndpoint() string {
	if t.Prefix == "" {
		return ""
	}
	return t.Prefix + "." + t.BaseDomain
}

func (t *Tenant) DoHEndpoint() string {
	if t.Prefix == "" {
		return ""
	}
	return "https://" + t.Prefix + "." + t.BaseDomain + "/dns-query"
}

type User struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"` // "" for platform admins
	Username       string    `json:"username"`
	PasswordHash   string    `json:"-"`
	Role           Role      `json:"role"`
	Email          string    `json:"email"`
	FailedAttempts int       `json:"-"`
	LockedUntil    time.Time `json:"-"`
	LastLogin      time.Time `json:"last_login"`
	CreatedAt      time.Time `json:"created_at"`
}

type UpstreamProtocol string

const (
	ProtoUDP UpstreamProtocol = "udp"
	ProtoTCP UpstreamProtocol = "tcp"
	ProtoDoT UpstreamProtocol = "dot"
	ProtoDoH UpstreamProtocol = "doh"
	ProtoDoQ UpstreamProtocol = "doq"
)

type Upstream struct {
	ID          string           `json:"id"`
	GroupID     string           `json:"group_id"`
	Name        string           `json:"name"`
	Protocol    UpstreamProtocol `json:"protocol"`
	Address     string           `json:"address"` // IP or host (no port)
	Port        int              `json:"port"`
	Hostname    string           `json:"hostname"` // TLS SNI / DoH Host header
	DoHPath     string           `json:"doh_path"` // default /dns-query
	Weight      int              `json:"weight"`
	TimeoutMS   int              `json:"timeout_ms"`
	TLSInsecure bool             `json:"tls_insecure"` // dev only; never true in prod
	Enabled     bool             `json:"enabled"`
	Healthy     bool             `json:"healthy"` // runtime state (from health checks)
	ConsecFails int              `json:"-"`
	CreatedAt   time.Time        `json:"created_at"`
}

type UpstreamGroup struct {
	ID           string      `json:"id"`
	TenantID     string      `json:"tenant_id"` // "" = global group
	Name         string      `json:"name"`
	Strategy     string      `json:"strategy"` // round_robin | weighted | failover
	HealthDomain string      `json:"health_domain"`
	CreatedAt    time.Time   `json:"created_at"`
	Upstreams    []*Upstream `json:"upstreams,omitempty"`
}

type MatchType string

const (
	MatchSuffix MatchType = "suffix"
	MatchPrefix MatchType = "prefix"
	MatchExact  MatchType = "exact"
	MatchRegex  MatchType = "regex"
	MatchAll    MatchType = "all"
)

// SplitRule routes qnames to upstream groups ("分流").
type SplitRule struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"` // "" = global rule
	Name       string    `json:"name"`
	MatchType  MatchType `json:"match_type"`
	MatchValue string    `json:"match_value"`
	GroupID    string    `json:"group_id"`
	Priority   int       `json:"priority"` // higher wins
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

type HotDomain struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"` // "" = global hot list
	Domain   string `json:"domain"`
	Weight   int    `json:"weight"`
	Enabled  bool   `json:"enabled"`
}

// QueryLogRow is one DNS query record written to MySQL asynchronously.
type QueryLogRow struct {
	TS          time.Time `json:"ts"`
	TenantID    string    `json:"tenant_id"`
	ClientIP    string    `json:"client_ip"`
	ECS         string    `json:"ecs"`
	QName       string    `json:"qname"`
	QType       string    `json:"qtype"`
	RCode       string    `json:"rcode"`
	CacheHit    bool      `json:"cache_hit"`
	UpstreamGrp string    `json:"upstream_group"`
	Upstream    string    `json:"upstream"`
	RTTMS       int       `json:"rtt_ms"`
	DNSSECOK    bool      `json:"dnssec_ok"`
	VIP         bool      `json:"vip"`
	Via         string    `json:"via"` // udp|tcp|dot|doh|doq
}

type AuditRow struct {
	TS        time.Time `json:"ts"`
	ActorID   string    `json:"actor_id"`
	ActorName string    `json:"actor_name"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"` // JSON string
	ClientIP  string    `json:"client_ip"`
}

// SimulateResult is returned by the ECS simulation API ("前端ecs模拟"):
// it shows exactly how a query with a given ECS would traverse the pipeline.
type SimulateResult struct {
	QName           string        `json:"qname"`
	QType           string        `json:"qtype"`
	ECSRequested    string        `json:"ecs_requested"`
	ECSUsed         string        `json:"ecs_used"`
	TenantID        string        `json:"tenant_id"`
	TenantName      string        `json:"tenant_name"`
	CacheHit        bool          `json:"cache_hit"`
	UpstreamGroup   string        `json:"upstream_group"`
	Upstream        string        `json:"upstream"`
	RTTMS           int           `json:"rtt_ms"`
	RCode           string        `json:"rcode"`
	DNSSECValidated bool          `json:"dnssec_validated"`
	VIP             bool          `json:"vip"`
	Answers         []AnswerBrief `json:"answers"`
	RuleMatched     string        `json:"rule_matched"` // which split rule fired
}

type AnswerBrief struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}
