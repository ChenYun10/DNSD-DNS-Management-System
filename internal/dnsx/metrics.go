package dnsx

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Stats keeps per-instance rolling counters (1-minute window of 1s buckets)
// plus cumulative totals. Snapshots can be pushed to Redis for a
// multi-instance overview (see FlushToRedis in the Core).
type Stats struct {
	mu       sync.Mutex
	window   [60]bucket
	cur      int
	started  time.Time
	totalQ   atomic.Uint64
	totalHit atomic.Uint64
	totalErr atomic.Uint64
}

type bucket struct {
	q, hit, miss, err uint64
}

func NewStats() *Stats { return &Stats{started: time.Now()} }

func (s *Stats) IncQuery() { s.bump(func(b *bucket) { b.q++ }); s.totalQ.Add(1) }
func (s *Stats) IncHit()   { s.bump(func(b *bucket) { b.hit++ }); s.totalHit.Add(1) }
func (s *Stats) IncMiss()  { s.bump(func(b *bucket) { b.miss++ }) }
func (s *Stats) IncError() { s.bump(func(b *bucket) { b.err++ }); s.totalErr.Add(1) }

func (s *Stats) bump(f func(*bucket)) {
	now := time.Now()
	s.mu.Lock()
	idx := now.Second() % 60
	if idx != s.cur {
		s.cur = idx
		s.window[idx] = bucket{}
	}
	f(&s.window[idx])
	s.mu.Unlock()
}

// Snapshot returns qps, hit-rate and error-rate over the last 60s.
func (s *Stats) Snapshot() (qps float64, hitRate float64, errRate float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var q, hit, err uint64
	for i := 0; i < 60; i++ {
		q += s.window[i].q
		hit += s.window[i].hit
		err += s.window[i].err
	}
	qps = float64(q) / 60.0
	if q > 0 {
		hitRate = float64(hit) / float64(q) * 100.0
		errRate = float64(err) / float64(q) * 100.0
	}
	return
}

func (s *Stats) Totals() (q, hit, err uint64) {
	return s.totalQ.Load(), s.totalHit.Load(), s.totalErr.Load()
}

// FlushToRedis writes the current snapshot + totals into a shared Redis key
// so that the control plane (apid) can read cross-instance statistics.
// Key: dns:stats:overview (HSET fields qps/hit_rate_pct/error_rate_pct/total_queries/total_hits/total_errors/instance_id).
func (s *Stats) FlushToRedis(ctx context.Context, rdb *redis.Client, instanceID string) error {
	qps, hitRate, errRate := s.Snapshot()
	q, hit, err := s.Totals()
	return rdb.HSet(ctx, "dns:stats:overview", map[string]any{
		"instance_id":    instanceID,
		"qps":            qps,
		"hit_rate_pct":   hitRate,
		"error_rate_pct": errRate,
		"total_queries":  q,
		"total_hits":     hit,
		"total_errors":   err,
		"updated_at":     time.Now().Unix(),
	}).Err()
}

// ---------------------------------------------------------------------------
// Per-upstream / per-tenant counters (simple, thread-safe)
// ---------------------------------------------------------------------------

type CounterSet struct {
	mu sync.Mutex
	m  map[string]*uint64
}

func NewCounterSet() *CounterSet { return &CounterSet{m: make(map[string]*uint64)} }

func (c *CounterSet) Inc(key string) {
	c.mu.Lock()
	p, ok := c.m[key]
	if !ok {
		p = new(uint64)
		c.m[key] = p
	}
	*p++
	c.mu.Unlock()
}

func (c *CounterSet) Get(key string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.m[key]; ok {
		return *p
	}
	return 0
}

func (c *CounterSet) Snapshot() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.m))
	for k, v := range c.m {
		out[k] = *v
	}
	return out
}
