package dnsx

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
	"dns-platform/internal/store"
)

// Core is the DNS request pipeline shared by all listeners
// (UDP / TCP / DoT / DoH / DoQ) and the ECS simulation API:
//
//	parse → tenant resolve → rate limit → ECS extract → cache lookup →
//	singleflight → split/分流 → upstream failover → DNSSEC policy →
//	cache write → async MySQL log → metrics
type Core struct {
	cfg      *config.Config
	cache    *AnswerCache
	cacheDrv store.Cache
	logger   *store.QueryLogWriter
	repos    *store.Repos
	up       *Manager
	split    *Splitter
	sec      *Validator
	warm     *WarmupManager
	limiter  *Limiter
	stats    *Stats

	dualstack *Dualstack // IPv6→IPv4 ECS 推导 + 归属地/运营商校验

	byUpstream *CounterSet // upstream -> queries
	byTenant   *CounterSet // tenant -> queries

	hotLoaded bool
}

// RequestMeta carries transport-level context into the pipeline
// (DoT SNI prefix, DoH host, etc).
type RequestMeta struct {
	Via           string // udp|tcp|dot|doh|doq
	SNI           string // raw SNI/host used by the client
	Prefix        string // tenant prefix extracted from SNI
	Tenant        *model.Tenant
	ClientIP      net.IP
	Internal      bool     // 请求来自内网专用监听器（触发 IPv6→IPv4 ECS 推导）
	SimulateECS   *ECSInfo // set only for ECS simulation requests
	SkipRateLimit bool     // set for API-driven simulation
}

func NewCore(cfg *config.Config, cacheDrv store.Cache, logger *store.QueryLogWriter, repos *store.Repos, rdb *redis.Client) *Core {
	c := &Core{
		cfg:        cfg,
		cacheDrv:   cacheDrv,
		cache:      NewAnswerCache(cfg, cacheDrv),
		logger:     logger,
		repos:      repos,
		up:         NewManager(cfg),
		split:      NewSplitter(),
		sec:        NewValidator(cfg.DNSSECMode),
		limiter:    NewLimiter(rdb, cfg.RateLimitQPS, cfg.RateLimitVIPMult),
		stats:      NewStats(),
		dualstack:  NewDualstack(cfg),
		byUpstream: NewCounterSet(),
		byTenant:   NewCounterSet(),
	}
	c.warm = NewWarmupManager(cfg, rdb, c)
	// adaptive warm hook: hot entries near expiry refresh in background
	c.cache.warmHook = func(tenantID, key, qname, qtype string, ecs *ECSInfo, ttlLeft time.Duration) {
		if !isHotDomain(rdb, tenantID, qname) {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.UpstreamTimeout+2*time.Second)
			defer cancel()
			tenant, err := repos.GetTenant(ctx, tenantID)
			if err != nil || tenant == nil {
				return
			}
			req := new(dns.Msg)
			req.SetQuestion(dns.Fqdn(qname), qtypeFromString(qtype))
			req.SetEdns0(1232, true)
			if ecs != nil {
				req = attachECS(req, ecs)
			}
			c.fetchAndCache(ctx, tenant, req, ecs, nil, "adaptive-warm")
		}()
	}
	return c
}

// UpstreamManager exposes the manager for reload wiring.
func (c *Core) UpstreamManager() *Manager { return c.up }

// ReloadAll refreshes rules/groups/upstreams/hot list from the repositories.
func (c *Core) ReloadAll(ctx context.Context) error {
	groups, err := c.repos.ListGroups(ctx)
	if err != nil {
		return err
	}
	upstreams, err := c.repos.ListUpstreams(ctx)
	if err != nil {
		return err
	}
	tenants, err := c.repos.ListTenants(ctx)
	if err != nil {
		return err
	}
	rules, err := c.repos.ListRules(ctx)
	if err != nil {
		return err
	}
	hots, err := c.repos.ListHotDomains(ctx)
	if err != nil {
		return err
	}
	c.up.Reload(groups, upstreams, tenants)
	c.split.Reload(rules)
	c.reloadHotSet(ctx, hots)

	// 双栈绑定表（可选；表缺失/查询失败不影响主流程，仅记录告警）
	if c.dualstack != nil {
		bindings, berr := c.repos.ListDualstackBindings(ctx)
		if berr != nil {
			log.Printf("[config] load dualstack bindings failed (ignored): %v", berr)
			c.dualstack.Reload(nil)
		} else {
			c.dualstack.Reload(bindings)
		}
	}
	return nil
}

func (c *Core) reloadHotSet(ctx context.Context, hots []*model.HotDomain) {
	if c.warm.rdb == nil {
		return
	}
	byTenant := map[string][]string{}
	for _, h := range hots {
		if !h.Enabled {
			continue
		}
		tid := h.TenantID
		if tid == "" {
			tid = "*"
		}
		byTenant[tid] = append(byTenant[tid], strings.ToLower(h.Domain))
	}
	pipe := c.warm.rdb.Pipeline()
	for tid, domains := range byTenant {
		key := "dns:hot:" + store.Safe(tid)
		pipe.Del(ctx, key)
		if len(domains) > 0 {
			pipe.SAdd(ctx, key, domains)
		}
	}
	pipe.Exec(ctx)
	c.hotLoaded = true
}

// Stats returns the rolling stats object.
func (c *Core) Stats() *Stats { return c.stats }

// DNSSECStats returns validator counters (verified / failed RRsets).
func (c *Core) DNSSECStats() (ok, fail uint64) { return c.sec.Stats() }

// TenantQueries returns the per-tenant query counter.
func (c *Core) TenantQueries(tenantID string) uint64 {
	return c.byTenant.Get(tenantIDOr(tenantID, "default"))
}

// UpstreamQueries returns the per-upstream query counter.
func (c *Core) UpstreamQueries() map[string]uint64 {
	return c.byUpstream.Snapshot()
}

// UpstreamHealth returns the current health snapshot of all upstreams.
func (c *Core) UpstreamHealth() map[string]bool {
	return c.up.HealthSnapshot()
}

// PingCache verifies cache connectivity (used by /readyz).
func (c *Core) PingCache(ctx context.Context) error {
	return c.cacheDrv.Ping(ctx)
}

// CacheKeys returns the active cache driver (for purge operations).
func (c *Core) CacheDriver() store.Cache { return c.cacheDrv }

// Warmup exposes the warmup manager (for API-driven pre-warming).
func (c *Core) Warmup() *WarmupManager { return c.warm }

// Limiter exposes the DNS rate limiter.
func (c *Core) Limiter() *Limiter { return c.limiter }

// ServeDNS implements dns.Handler (UDP/TCP/DoT).
func (c *Core) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	meta := &RequestMeta{Via: "udp"}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		meta.Via = "tcp"
	}
	if cw, ok := w.(*ctxWriter); ok {
		meta.SNI = cw.sni
		meta.Prefix = cw.prefix
		meta.Tenant = cw.tenant
		meta.ClientIP = cw.clientIP
		meta.Internal = cw.internal
		if cw.via != "" {
			meta.Via = cw.via
		}
	}
	if meta.ClientIP == nil {
		meta.ClientIP = clientIP(w.RemoteAddr())
	}
	resp, _ := c.Process(context.Background(), r, meta)
	if resp == nil {
		return
	}
	_ = w.WriteMsg(resp)
}

// Process runs the full pipeline. Returns the response and metadata used for
// logging/simulation.
func (c *Core) Process(ctx context.Context, req *dns.Msg, meta *RequestMeta) (*dns.Msg, *RespMeta) {
	rm := &RespMeta{}
	start := time.Now()
	c.stats.IncQuery()

	if req == nil || len(req.Question) == 0 {
		return refuse(req), rm
	}
	q := req.Question[0]

	// --- basic validation / protocol hygiene ---
	if len(q.Name) > 253 || strings.Count(q.Name, ".") > 127 {
		return refuse(req), rm
	}
	if opt := req.IsEdns0(); opt != nil && opt.Version() != 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeBadVers)
		return m, rm
	}

	// --- tenant resolution (from DoT SNI / DoH host, else default) ---
	tenant := meta.Tenant
	if tenant == nil && meta.Prefix != "" {
		if t, err := c.repos.TenantByPrefix(ctx, meta.Prefix); err == nil {
			tenant = t
		}
	}
	tenantID := ""
	vip := false
	if tenant != nil {
		tenantID = tenant.ID
		vip = tenant.VIP
	}
	c.byTenant.Inc(tenantIDOr(tenantID, "default"))

	// --- rate limit ---
	ipStr := ""
	if meta.ClientIP != nil {
		ipStr = meta.ClientIP.String()
	}
	if !meta.SkipRateLimit && !c.limiter.AllowDNS(ctx, tenantID, ipStr, vip) {
		c.stats.IncError()
		return rateLimited(req), rm
	}

	// --- ECS (模拟 / 传递 / 缓存作用域) ---
	ecs := ecsFromMsg(req)
	ecs.clampScope(c.cfg.ECSScopeMax) // 收敛客户端 ECS 前缀到 ECSScopeMax
	if meta.SimulateECS != nil {
		ecs = meta.SimulateECS
		ecs.clampScope(c.cfg.ECSScopeMax)
		req = attachECS(req, ecs) // rebuild the query with the simulated ECS
	}
	if ecs.HasOption && tenant != nil && !tenant.AllowECS {
		ecs = nil // tenant does not allow client-supplied ECS
		req = stripECS(req)
	}
	// 内网 IPv6 客户端：推导真实 IPv4 并透传为 ECS（仅当校验一致且无客户端 ECS）。
	if c.cfg.DualstackEnabled && meta.Internal && meta.ClientIP != nil && meta.ClientIP.To4() == nil {
		if ecs == nil || !ecs.HasOption {
			if derived := c.dualstack.DeriveECS(ctx, meta.ClientIP); derived != nil {
				ecs = derived
				req = attachECS(req, derived)
			}
		}
	}
	if (ecs == nil || !ecs.HasOption) && tenant != nil && tenant.DefaultECS != "" {
		if def, err := parseECSFromString(tenant.DefaultECS); err == nil {
			ecs = def
			req = attachECS(req, def)
		}
	}
	ecsKey := ecsToCacheString(ecs)
	if ecsKey != "" {
		c.warm.TrackActiveECS(ctx, tenantID, ecsKey)
	}

	qname := strings.ToLower(q.Name)
	cacheKey := store.CacheKey(tenantID, ecsKey, qname, dns.TypeToString[q.Qtype])

	// --- cache lookup ---
	if m, hit := c.cache.Get(ctx, cacheKey, req.Id); hit {
		c.stats.IncHit()
		rm.CacheHit = true
		rm.FromCache = true
		rm.RCode = dns.RcodeToString[m.Rcode]
		// adaptive pre-warm check for near-expiry hot entries
		if ent, _ := c.cacheDrv.Get(ctx, cacheKey); ent != nil {
			ttlLeft := time.Duration(ent.TTL-(time.Now().Unix()-ent.Stored)) * time.Second
			c.cache.ObserveAdaptiveWarm(ctx, tenantID, cacheKey, qname, dns.TypeToString[q.Qtype], ecs, ttlLeft)
		}
		rm.RTTMS = int(time.Since(start).Milliseconds())
		c.logQuery(req, meta, tenantID, ecsKey, qname, rm, vip)
		return m, rm
	}
	c.stats.IncMiss()

	// --- upstream resolution with 分流 ---
	groupID, ruleName := c.split.GroupForQuery(tenant, qname)
	if groupID == "" {
		groupID = c.cfg.DefaultGroup
	}
	rm.RuleMatched = ruleName
	group := c.up.GroupByName(groupID)

	// singleflight around the upstream exchange
	m, fmeta := c.cache.SingleFlight(ctx, cacheKey, func() (*dns.Msg, *RespMeta) {
		rm2 := &RespMeta{UpstreamGroup: groupID}
		resp, es, err := c.up.ExchangeWithFailover(ctx, group, req)
		if err != nil {
			c.stats.IncError()
			rm2.RCode = "SERVFAIL"
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			return m, rm2
		}
		if es != nil {
			rm2.Upstream = es.String()
			c.byUpstream.Inc(es.String())
		}
		rm2.RTTMS = int(time.Since(start).Milliseconds())

		// --- DNSSEC policy ---
		do := false
		if opt := req.IsEdns0(); opt != nil {
			do = opt.Do()
		}
		if do {
			rm2.DNSSECOK = c.sec.Validate(resp)
		}
		resp = stripECS(resp)
		echoECS(resp, ecs)
		resp.Id = req.Id
		resp.Compress = true

		// --- cache write ---
		if c.cache.Put(ctx, cacheKey, resp) > 0 {
			rm2.FromCache = false
		}
		rm2.RCode = dns.RcodeToString[resp.Rcode]
		rm2.CacheHit = false
		return resp, rm2
	})
	if fmeta != nil {
		rm.UpstreamGroup = fmeta.UpstreamGroup
		rm.Upstream = fmeta.Upstream
		rm.RTTMS = fmeta.RTTMS
		rm.DNSSECOK = fmeta.DNSSECOK
		rm.RCode = fmeta.RCode
	}
	if m == nil {
		m = refuse(req)
	}
	c.logQuery(req, meta, tenantID, ecsKey, qname, rm, vip)
	return m, rm
}

// fetchAndCache is the cache-bypass path used by warmup: fetch from upstream
// and write straight into the cache (dynamic pre-warming).
func (c *Core) fetchAndCache(ctx context.Context, tenant *model.Tenant, req *dns.Msg, ecs *ECSInfo, meta *RequestMeta, via string) (*dns.Msg, error) {
	tenantID := ""
	if tenant != nil {
		tenantID = tenant.ID
	}
	q := req.Question[0]
	ecsKey := ecsToCacheString(ecs)
	cacheKey := store.CacheKey(tenantID, ecsKey, strings.ToLower(q.Name), dns.TypeToString[q.Qtype])

	groupID, _ := c.split.GroupForQuery(tenant, q.Name)
	if groupID == "" {
		groupID = c.cfg.DefaultGroup
	}
	group := c.up.GroupByName(groupID)
	resp, es, err := c.up.ExchangeWithFailover(ctx, group, req)
	if err != nil {
		return nil, err
	}
	if es != nil {
		c.byUpstream.Inc(es.String())
	}
	if opt := req.IsEdns0(); opt != nil && opt.Do() {
		c.sec.Validate(resp)
	}
	resp = stripECS(resp)
	resp.Compress = true
	if c.cache.Put(ctx, cacheKey, resp) > 0 {
		c.warm.TrackActiveECS(ctx, tenantID, ecsKey)
	}
	return resp, nil
}

func (c *Core) logQuery(req *dns.Msg, meta *RequestMeta, tenantID, ecsKey, qname string, rm *RespMeta, vip bool) {
	if c.logger == nil || len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	ip := ""
	if meta != nil && meta.ClientIP != nil {
		ip = meta.ClientIP.String()
	}
	via := "udp"
	if meta != nil && meta.Via != "" {
		via = meta.Via
	}
	c.logger.Write(model.QueryLogRow{
		TS:          time.Now(),
		TenantID:    tenantID,
		ClientIP:    ip,
		ECS:         ecsKey,
		QName:       qname,
		QType:       dns.TypeToString[q.Qtype],
		RCode:       rm.RCode,
		CacheHit:    rm.CacheHit,
		UpstreamGrp: rm.UpstreamGroup,
		Upstream:    rm.Upstream,
		RTTMS:       rm.RTTMS,
		DNSSECOK:    rm.DNSSECOK,
		VIP:         vip,
		Via:         via,
	})
}

// --- helpers ---

func refuse(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	return m
}

func rateLimited(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: 11, ExtraText: "rate limited"})
	m.Extra = append(m.Extra, opt)
	return m
}

func clientIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	return nil
}

func tenantIDOr(id, def string) string {
	if id == "" {
		return def
	}
	return id
}

func qtypeFromString(s string) uint16 {
	if t, ok := dns.StringToType[s]; ok {
		return t
	}
	return dns.TypeA
}

// ctxWriter carries tenant/SNI metadata from the TLS layer into ServeDNS.
type ctxWriter struct {
	dns.ResponseWriter
	sni      string
	prefix   string
	tenant   *model.Tenant
	clientIP net.IP
	via      string
	internal bool
}

var _ = log.Printf // keep import when build tags change
