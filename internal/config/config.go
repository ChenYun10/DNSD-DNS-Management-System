// Package config loads and validates all runtime configuration for the DNS
// platform from environment variables (with optional .env file support).
//
// Production defaults require Redis (cache) + MySQL (logging/metadata).
// Dev-only drivers (memory cache / stdout logs) exist for local smoke tests
// and are clearly flagged — they are never used when ENV=prod.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// General
	Env        string // dev | prod
	InstanceID string // unique per process (for multi-instance stats)
	LogLevel   string // debug | info | warn | error

	// Public DNS identity (used for DoT/DoH endpoint construction)
	BaseDomain string // e.g. dns.example.com

	// Listeners (downstream, client-facing)
	DNSListenUDP string // traditional DNS over UDP, e.g. :53
	DNSListenTCP string // traditional DNS over TCP, e.g. :53
	DoTListen    string // DNS over TLS, e.g. :853
	DoHListen    string // DNS over HTTPS, e.g. :8443 (usually behind nginx on :443)
	DoQListen    string // DNS over QUIC (RFC 9250), e.g. :784

	// TLS for DoT/DoH/DoQ downstream. Wildcard cert for *.BaseDomain recommended.
	TLSCertFile string
	TLSKeyFile  string

	// Upstream defaults
	DefaultGroup      string        // default upstream group name for tenants without rules
	UpstreamTimeout   time.Duration // per-upstream exchange timeout
	HealthInterval    time.Duration // upstream health probe interval
	HealthDomain      string        // probe qname, e.g. health.example.com
	HealthFailsToDown int           // consecutive failures to mark unhealthy

	// Cache (Redis in production)
	CacheDriver   string // redis | memory(dev only)
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	CacheMaxTTL   time.Duration // clamp stored TTL
	NegCacheTTL   time.Duration // clamp negative answers
	// Adaptive pre-warm: when a cached entry's remaining TTL drops below this
	// threshold AND the qname is in the tenant's hot list, refresh async.
	WarmThreshold time.Duration

	// Query logging (MySQL in production)
	LogDriver        string // mysql | stdout(dev only)
	MySQLDSN         string
	LogBatchSize     int           // rows per batch insert
	LogFlushInterval time.Duration // max wait between flushes

	// DNSSEC
	DNSSECMode string // passthrough | ad-only | verify
	// If true, requests from validating upstreams that set AD propagate AD.
	RequireADFromUpstream bool

	// ECS (EDNS Client Subnet)
	ECSPassthrough bool // forward client ECS to upstreams that support it
	ECSScopeMax    int  // clamp scope to /0..32, default 24

	// Rate limiting
	RateLimitQPS     int // default per-IP QPS cap
	RateLimitVIPMult int // multiplier for VIP tenants
	LoginRateLimit   int // failed logins per IP per window
	LoginRateWindow  time.Duration

	// REST API
	APIListen      string // customer/admin API, e.g. :8080
	APIAdminListen string // dedicated admin channel (separate bind), e.g. :8443
	APIMTLSCAFile  string // optional: require client certs (mTLS) for admin/VIP channel
	APIJWTSecret   string // HMAC secret, min 32 chars
	JWTExpiry      time.Duration
	JWTRefreshExp  time.Duration
	APICORSOrigins []string

	// Warmup
	WarmupConcurrency int

	// Bootstrap: one-time admin setup token (BOOTSTRAP_TOKEN). When set, the
	// POST /api/v1/bootstrap/admin endpoint can create the initial admin
	// account. The endpoint disables itself once an admin exists.
	BootstrapToken string

	// Admin-managed SSL (ACME). Tenant custom main domains get certificates
	// issued/renewed automatically from the backend; the base wildcard cert
	// stays with the existing acme.sh flow (renew-dns-cert.sh).
	ACMEEnabled           bool          // master switch for the ACME manager
	ACMEEmail             string        // contact email for the CA
	ACMEStaging           bool          // use Let's Encrypt staging (avoid rate limits while testing)
	ACMEDirectoryURL      string        // explicit CA directory override
	CertDir               string        // cert root: {CertDir}/domains/<domain>/{fullchain.pem,privkey.pem}
	ACMEHTTPPort          string        // HTTP-01 challenge listener, e.g. 127.0.0.1:5002 (behind nginx)
	AliyunAccessKeyID     string        // for DNS-01 issuance on Aliyun-hosted domains
	AliyunAccessKeySecret string
	CertRenewBefore       time.Duration // renew when expiry is closer than this
}

// Load reads configuration from the environment. If path is non-empty and the
// file exists, it is parsed as KEY=VALUE lines first (dotenv style) and then
// overridden by real environment variables.
func Load(envFile string) (*Config, error) {
	if envFile != "" {
		loadDotEnv(envFile)
	}
	c := &Config{
		Env:                   getenv("ENV", "dev"),
		InstanceID:            getenv("INSTANCE_ID", "inst-"+hostname()),
		LogLevel:              getenv("LOG_LEVEL", "info"),
		BaseDomain:            getenv("BASE_DOMAIN", "dns.example.com"),
		DNSListenUDP:          getenv("DNS_LISTEN_UDP", ":53"),
		DNSListenTCP:          getenv("DNS_LISTEN_TCP", ":53"),
		DoTListen:             getenv("DOT_LISTEN", ":853"),
		DoHListen:             getenv("DOH_LISTEN", ":8443"),
		DoQListen:             getenv("DOQ_LISTEN", ":784"),
		TLSCertFile:           getenv("TLS_CERT_FILE", ""),
		TLSKeyFile:            getenv("TLS_KEY_FILE", ""),
		DefaultGroup:          getenv("DEFAULT_UPSTREAM_GROUP", "default"),
		UpstreamTimeout:       getdur("UPSTREAM_TIMEOUT", 4*time.Second),
		HealthInterval:        getdur("HEALTH_INTERVAL", 30*time.Second),
		HealthDomain:          getenv("HEALTH_DOMAIN", "health-check.example.com"),
		HealthFailsToDown:     getint("HEALTH_FAILS_TO_DOWN", 3),
		CacheDriver:           getenv("CACHE_DRIVER", "redis"),
		RedisAddr:             getenv("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:         getenv("REDIS_PASSWORD", ""),
		RedisDB:               getint("REDIS_DB", 0),
		CacheMaxTTL:           getdur("CACHE_MAX_TTL", 6*time.Hour),
		NegCacheTTL:           getdur("NEG_CACHE_TTL", 30*time.Second),
		WarmThreshold:         getdur("WARM_THRESHOLD", 60*time.Second),
		LogDriver:             getenv("LOG_DRIVER", "mysql"),
		MySQLDSN:              getenv("MYSQL_DSN", "dns:dns@tcp(127.0.0.1:3306)/dns_platform?parseTime=true&charset=utf8mb4"),
		LogBatchSize:          getint("LOG_BATCH_SIZE", 500),
		LogFlushInterval:      getdur("LOG_FLUSH_INTERVAL", 2*time.Second),
		DNSSECMode:            getenv("DNSSEC_MODE", "ad-only"),
		RequireADFromUpstream: getbool("DNSSEC_REQUIRE_AD", true),
		ECSPassthrough:        getbool("ECS_PASSTHROUGH", true),
		ECSScopeMax:           getint("ECS_SCOPE_MAX", 24),
		RateLimitQPS:          getint("RATE_LIMIT_QPS", 100),
		RateLimitVIPMult:      getint("RATE_LIMIT_VIP_MULT", 10),
		LoginRateLimit:        getint("LOGIN_RATE_LIMIT", 10),
		LoginRateWindow:       getdur("LOGIN_RATE_WINDOW", 10*time.Minute),
		APIListen:             getenv("API_LISTEN", ":8080"),
		APIAdminListen:        getenv("API_ADMIN_LISTEN", ":8443"),
		APIMTLSCAFile:         getenv("API_MTLS_CA_FILE", ""),
		APIJWTSecret:          getenv("API_JWT_SECRET", ""),
		JWTExpiry:             getdur("JWT_EXPIRY", 15*time.Minute),
		JWTRefreshExp:         getdur("JWT_REFRESH_EXPIRY", 7*24*time.Hour),
		APICORSOrigins:        splitCSV(getenv("API_CORS_ORIGINS", "http://localhost:8081,http://127.0.0.1:8081")),
		WarmupConcurrency:     getint("WARMUP_CONCURRENCY", 32),
		BootstrapToken:        getenv("BOOTSTRAP_TOKEN", ""),
		ACMEEnabled:           getbool("ACME_ENABLED", false),
		ACMEEmail:             getenv("ACME_EMAIL", ""),
		ACMEStaging:           getbool("ACME_STAGING", false),
		ACMEDirectoryURL:      getenv("ACME_DIRECTORY_URL", ""),
		CertDir:               getenv("CERT_DIR", "/etc/dns-platform/certs"),
		ACMEHTTPPort:          getenv("ACME_HTTP_PORT", "127.0.0.1:5002"),
		AliyunAccessKeyID:     getenv("ALIYUN_ACCESS_KEY_ID", ""),
		AliyunAccessKeySecret: getenv("ALIYUN_ACCESS_KEY_SECRET", ""),
		CertRenewBefore:       getdur("CERT_RENEW_BEFORE", 720*time.Hour),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	var errs []string
	if c.Env != "dev" && c.Env != "prod" {
		errs = append(errs, "ENV must be dev or prod")
	}
	if c.BaseDomain == "" || !strings.Contains(c.BaseDomain, ".") {
		errs = append(errs, "BASE_DOMAIN must be a FQDN like dns.example.com")
	}
	if c.TLSCertFile == "" || c.TLSKeyFile == "" {
		errs = append(errs, "TLS_CERT_FILE and TLS_KEY_FILE are required (wildcard cert for *."+c.BaseDomain+")")
	}
	if _, err := os.Stat(c.TLSCertFile); err != nil {
		errs = append(errs, "TLS_CERT_FILE not readable: "+err.Error())
	}
	if _, err := os.Stat(c.TLSKeyFile); err != nil {
		errs = append(errs, "TLS_KEY_FILE not readable: "+err.Error())
	}
	if c.CacheDriver == "redis" {
		if c.RedisAddr == "" {
			errs = append(errs, "REDIS_ADDR required when CACHE_DRIVER=redis")
		}
	} else if c.CacheDriver != "memory" {
		errs = append(errs, "CACHE_DRIVER must be redis or memory")
	} else if c.Env == "prod" {
		errs = append(errs, "CACHE_DRIVER=memory is forbidden in prod")
	}
	if c.LogDriver == "mysql" {
		if c.MySQLDSN == "" {
			errs = append(errs, "MYSQL_DSN required when LOG_DRIVER=mysql")
		}
	} else if c.LogDriver != "stdout" {
		errs = append(errs, "LOG_DRIVER must be mysql or stdout")
	} else if c.Env == "prod" {
		errs = append(errs, "LOG_DRIVER=stdout is forbidden in prod")
	}
	if c.DNSSECMode != "passthrough" && c.DNSSECMode != "ad-only" && c.DNSSECMode != "verify" {
		errs = append(errs, "DNSSEC_MODE must be passthrough|ad-only|verify")
	}
	if len(c.APIJWTSecret) < 32 {
		errs = append(errs, "API_JWT_SECRET must be at least 32 chars (generate with: openssl rand -hex 32)")
	}
	if c.ECSScopeMax < 0 || c.ECSScopeMax > 32 {
		errs = append(errs, "ECS_SCOPE_MAX must be 0..32")
	}
	if c.RateLimitQPS <= 0 {
		errs = append(errs, "RATE_LIMIT_QPS must be > 0")
	}
	for _, l := range []struct{ name, addr string }{{"DNS_LISTEN_UDP", c.DNSListenUDP}, {"DNS_LISTEN_TCP", c.DNSListenTCP}, {"DOT_LISTEN", c.DoTListen}, {"DOH_LISTEN", c.DoHListen}, {"DOQ_LISTEN", c.DoQListen}, {"API_LISTEN", c.APIListen}, {"API_ADMIN_LISTEN", c.APIAdminListen}} {
		if _, _, err := net.SplitHostPort(l.addr); err != nil {
			errs = append(errs, l.name+" invalid: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("config validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// --- helpers ---

func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
}

func getenv(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func getint(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getbool(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func getdur(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
