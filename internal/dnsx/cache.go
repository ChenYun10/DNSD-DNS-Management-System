package dnsx

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"

	"dns-platform/internal/config"
	"dns-platform/internal/store"
)

// AnswerCache wraps the Redis cache with DNS semantics:
//   - per-tenant, per-ECS keying
//   - TTL adjustment on read (remaining TTL is reflected in the response)
//   - negative caching (SOA minimum)
//   - in-process singleflight (cache stampede protection)
//   - adaptive pre-warm hook: hot entries whose TTL is running low trigger an
//     asynchronous refresh, so cached data is kept warm dynamically.
type AnswerCache struct {
	cfg   *config.Config
	cache store.Cache

	sfMu     sync.Mutex
	inflight map[string]*flight

	warmHook func(tenantID, key, qname, qtype string, ecs *ECSInfo, ttlLeft time.Duration)
}

type flight struct {
	done chan struct{}
	msg  *dns.Msg
	meta *RespMeta
}

type RespMeta struct {
	CacheHit      bool
	UpstreamGroup string
	Upstream      string
	RTTMS         int
	DNSSECOK      bool
	RuleMatched   string
	FromCache     bool
	RCode         string
}

func NewAnswerCache(cfg *config.Config, cache store.Cache) *AnswerCache {
	return &AnswerCache{cfg: cfg, cache: cache, inflight: make(map[string]*flight)}
}

// Get returns a cached response for the key, adjusting TTLs to the remaining
// lifetime. Returns (nil, nil) on miss.
func (c *AnswerCache) Get(ctx context.Context, key string, msgID uint16) (*dns.Msg, bool) {
	ent, err := c.cache.Get(ctx, key)
	if err != nil || ent == nil {
		return nil, false
	}
	raw, err := store.UnpackMsg(ent.MsgB64)
	if err != nil {
		return nil, false
	}
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return nil, false
	}
	elapsed := time.Now().Unix() - ent.Stored
	ttlLeft := ent.TTL - elapsed
	if ttlLeft <= 0 {
		return nil, false // expired (Redis TTL should have caught this)
	}
	adjustTTLs(m, uint32(ttlLeft))
	m.Id = msgID
	return m, true
}

// Put stores a response with a computed TTL. Negative answers use the SOA
// minimum. Returns the effective TTL stored.
func (c *AnswerCache) Put(ctx context.Context, key string, m *dns.Msg) int64 {
	ttl := msgTTL(m, c.cfg)
	if ttl <= 0 {
		return 0 // do not cache e.g. SERVFAIL
	}
	maxTTL := int64(c.cfg.CacheMaxTTL.Seconds())
	if isNegative(m) && c.cfg.NegCacheTTL > 0 && int64(c.cfg.NegCacheTTL.Seconds()) < ttl {
		ttl = int64(c.cfg.NegCacheTTL.Seconds())
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	if ttl < 1 {
		ttl = 1
	}
	raw, err := m.Pack()
	if err != nil {
		return 0
	}
	ent := &store.CacheEntry{MsgB64: store.PackMsg(raw), Stored: time.Now().Unix(), TTL: ttl}
	_ = c.cache.Set(ctx, key, ent)
	return ttl
}

// SingleFlight executes fn once per key; concurrent callers for the same key
// wait for the same result instead of stampeding upstreams.
func (c *AnswerCache) SingleFlight(ctx context.Context, key string, fn func() (*dns.Msg, *RespMeta)) (*dns.Msg, *RespMeta) {
	c.sfMu.Lock()
	if f, ok := c.inflight[key]; ok {
		c.sfMu.Unlock()
		select {
		case <-f.done:
			return f.msg, f.meta
		case <-ctx.Done():
			return nil, &RespMeta{}
		}
	}
	f := &flight{done: make(chan struct{})}
	c.inflight[key] = f
	c.sfMu.Unlock()

	f.msg, f.meta = fn()
	if f.meta == nil {
		f.meta = &RespMeta{}
	}

	c.sfMu.Lock()
	delete(c.inflight, key)
	c.sfMu.Unlock()
	close(f.done)
	return f.msg, f.meta
}

// ObserveAdaptiveWarm is called on cache hits: if the entry is in the hot set
// and its remaining TTL is below the threshold, schedule a background refresh.
func (c *AnswerCache) ObserveAdaptiveWarm(ctx context.Context, tenantID, key, qname, qtype string, ecs *ECSInfo, ttlLeft time.Duration) {
	if c.warmHook == nil {
		return
	}
	if ttlLeft > c.cfg.WarmThreshold {
		return
	}
	c.warmHook(tenantID, key, qname, qtype, ecs, ttlLeft)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func adjustTTLs(m *dns.Msg, ttl uint32) {
	for _, rr := range m.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range m.Ns {
		rr.Header().Ttl = ttl
	}
	// keep extra (OPT) as-is
}

func msgTTL(m *dns.Msg, cfg *config.Config) int64 {
	if len(m.Answer) > 0 {
		min := uint32(1<<31 - 1)
		for _, rr := range m.Answer {
			if rr.Header().Ttl < min {
				min = rr.Header().Ttl
			}
		}
		return int64(min)
	}
	if m.Rcode == dns.RcodeSuccess && len(m.Ns) > 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				return int64(soa.Minttl)
			}
		}
	}
	return 0
}

func isNegative(m *dns.Msg) bool {
	return m.Rcode == dns.RcodeNameError || m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0
}
