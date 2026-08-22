package dnsx

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// L1Cache is a process-local DNS answer cache in front of Redis (L2).
//
// Rationale: the old hot path issued 1-3 Redis round-trips per query (rate
// limit INCR, cache GET, TTL re-read, hot-set SISMEMBER). At high QPS the
// network RTT dominates and DNS answers that should take <1ms end up paying
// multiple RTTs. L1 keeps the hottest answers in-process:
//
//   - 64 shards so there is no single global lock
//   - entries stored as packed bytes (no base64/JSON round-trip, unpack only)
//   - per-entry TTL capped by maxTTL (default 60s): a peer instance's cache
//     purge can delay at most maxTTL; Redis pub/sub invalidates sooner
//   - capacity bounded: on overflow, expired entries are dropped first, then
//     one arbitrary entry per shard
const (
	l1Shards     = 64
	l1DefaultMax = 131072 // total entry cap
	l1DefaultTTL = 60     // seconds — max time an entry lives in L1
)

type l1Entry struct {
	raw    []byte // packed dns.Msg
	stored int64  // unix seconds
	ttl    int64  // seconds (already capped at maxTTL)
}

type l1Shard struct {
	mu sync.RWMutex
	m  map[string]*l1Entry
}

// L1Cache is safe for concurrent use.
type L1Cache struct {
	shards      [l1Shards]*l1Shard
	maxPerShard int
	maxTTL      int64
}

func NewL1Cache(maxEntries, maxTTLSeconds int) *L1Cache {
	if maxEntries <= 0 {
		maxEntries = l1DefaultMax
	}
	if maxTTLSeconds <= 0 {
		maxTTLSeconds = l1DefaultTTL
	}
	c := &L1Cache{maxPerShard: maxEntries / l1Shards, maxTTL: int64(maxTTLSeconds)}
	for i := range c.shards {
		c.shards[i] = &l1Shard{m: make(map[string]*l1Entry)}
	}
	return c
}

func (c *L1Cache) shard(key string) *l1Shard {
	return c.shards[fnv32(key)%l1Shards]
}

// Get returns the entry if present and not expired.
func (c *L1Cache) Get(key string) (*l1Entry, bool) {
	s := c.shard(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := time.Now().Unix()
	if now-e.stored >= e.ttl || now-e.stored >= c.maxTTL {
		return nil, false
	}
	return e, true
}

// Put stores packed bytes with the given TTL (capped at maxTTL).
func (c *L1Cache) Put(key string, raw []byte, ttl int64) {
	if ttl <= 0 {
		return
	}
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	s := c.shard(key)
	s.mu.Lock()
	if _, ok := s.m[key]; !ok && len(s.m) >= c.maxPerShard {
		now := time.Now().Unix()
		for k, e := range s.m {
			if now-e.stored >= e.ttl || now-e.stored >= c.maxTTL {
				delete(s.m, k)
			}
		}
		if len(s.m) >= c.maxPerShard {
			for k := range s.m {
				delete(s.m, k)
				break
			}
		}
	}
	s.m[key] = &l1Entry{raw: raw, stored: time.Now().Unix(), ttl: ttl}
	s.mu.Unlock()
}

// Del removes a single key.
func (c *L1Cache) Del(key string) {
	s := c.shard(key)
	s.mu.Lock()
	delete(s.m, key)
	s.mu.Unlock()
}

// PurgePrefix deletes all keys with the given prefix. Returns the count
// removed. Used by the cache-purge API and Redis pub/sub invalidation.
func (c *L1Cache) PurgePrefix(prefix string) int64 {
	var n int64
	for _, s := range c.shards {
		s.mu.Lock()
		for k := range s.m {
			if strings.HasPrefix(k, prefix) {
				delete(s.m, k)
				n++
			}
		}
		s.mu.Unlock()
	}
	return n
}

// Len returns the total number of entries (for monitoring).
func (c *L1Cache) Len() int {
	var n int
	for _, s := range c.shards {
		s.mu.RLock()
		n += len(s.m)
		s.mu.RUnlock()
	}
	return n
}

// fnv32 is a tiny non-crypto hash used for key sharding.
func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// unpackL1 turns a stored entry into a dns.Msg with adjusted TTLs and ID.
func unpackL1(e *l1Entry, msgID uint16) *dns.Msg {
	m := new(dns.Msg)
	if err := m.Unpack(e.raw); err != nil {
		return nil
	}
	ttlLeft := uint32(e.stored + e.ttl - time.Now().Unix())
	if ttlLeft < 1 {
		ttlLeft = 1
	}
	adjustTTLs(m, ttlLeft)
	m.Id = msgID
	return m
}
