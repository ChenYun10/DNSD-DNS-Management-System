// Package store implements the two data planes required by the platform:
//   - Redis: high-performance cache (DNS answers, per-ECS), rate limiting,
//     active-ECS tracking, JWT blacklist, warmup status. This is the
//     "高效数据库" for hot DNS data.
//   - MySQL: query logs, audit logs and management metadata (tenants,
//     upstreams, split rules, hot domains).
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheEntry is the value stored in Redis for one DNS answer.
type CacheEntry struct {
	MsgB64 string `json:"m"`  // packed dns.Msg (base64)
	Stored int64  `json:"at"` // unix seconds when stored
	TTL    int64  `json:"ttl"`
}

// Cache is the DNS answer cache interface. Production uses Redis; a
// process-local memory cache exists for dev-only smoke tests.
type Cache interface {
	Ping(ctx context.Context) error
	Get(ctx context.Context, key string) (*CacheEntry, error)
	Set(ctx context.Context, key string, e *CacheEntry) error
	Del(ctx context.Context, keys ...string) error
	// Purge removes all keys under a prefix (tenant / tenant+qname).
	Purge(ctx context.Context, prefix string) (int64, error)
	Close() error
}

// ---------------------------------------------------------------------------
// Redis cache
// ---------------------------------------------------------------------------

type RedisCache struct {
	rdb *redis.Client
}

func NewRedisCache(addr, password string, db int) (*RedisCache, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           db,
		PoolSize:     128,
		MinIdleConns: 16,
		PoolTimeout:  5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &RedisCache{rdb: rdb}, nil
}

func (r *RedisCache) Ping(ctx context.Context) error { return r.rdb.Ping(ctx).Err() }

func (r *RedisCache) Get(ctx context.Context, key string) (*CacheEntry, error) {
	raw, err := r.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var e CacheEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (r *RedisCache) Set(ctx context.Context, key string, e *CacheEntry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	ttl := time.Duration(e.TTL) * time.Second
	if ttl <= 0 {
		ttl = 1
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	return r.rdb.Set(ctx, key, raw, ttl).Err()
}

func (r *RedisCache) Del(ctx context.Context, keys ...string) error {
	return r.rdb.Del(ctx, keys...).Err()
}

// Purge scans keys by prefix and deletes them (SCAN, never KEYS — no Redis
// blocking).
func (r *RedisCache) Purge(ctx context.Context, prefix string) (int64, error) {
	var deleted int64
	iter := r.rdb.Scan(ctx, 0, prefix+"*", 500).Iterator()
	for iter.Next(ctx) {
		if err := r.rdb.Del(ctx, iter.Val()).Err(); err == nil {
			deleted++
		}
	}
	return deleted, iter.Err()
}

func (r *RedisCache) Close() error { return r.rdb.Close() }

// ---------------------------------------------------------------------------
// Memory cache (dev only — never used with ENV=prod)
// ---------------------------------------------------------------------------

type MemoryCache struct {
	mu   sync.RWMutex
	m    map[string]*CacheEntry
	stop chan struct{}
}

func NewMemoryCache() *MemoryCache {
	c := &MemoryCache{m: make(map[string]*CacheEntry), stop: make(chan struct{})}
	go c.sweeper()
	return c
}

func (c *MemoryCache) sweeper() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case now := <-t.C:
			c.mu.Lock()
			for k, e := range c.m {
				if now.Unix()-e.Stored >= e.TTL {
					delete(c.m, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *MemoryCache) Ping(ctx context.Context) error { return nil }
func (c *MemoryCache) Get(ctx context.Context, key string) (*CacheEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[key]
	if !ok {
		return nil, nil
	}
	cp := *e
	return &cp, nil
}
func (c *MemoryCache) Set(ctx context.Context, key string, e *CacheEntry) error {
	c.mu.Lock()
	c.m[key] = e
	c.mu.Unlock()
	return nil
}
func (c *MemoryCache) Del(ctx context.Context, keys ...string) error {
	c.mu.Lock()
	for _, k := range keys {
		delete(c.m, k)
	}
	c.mu.Unlock()
	return nil
}
func (c *MemoryCache) Purge(ctx context.Context, prefix string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var n int64
	for k := range c.m {
		if strings.HasPrefix(k, prefix) {
			delete(c.m, k)
			n++
		}
	}
	return n, nil
}
func (c *MemoryCache) Close() error {
	close(c.stop)
	return nil
}

// ---------------------------------------------------------------------------
// Key helpers (shared by cache + tracking)
// ---------------------------------------------------------------------------

// CacheKey builds the per-tenant, per-ECS cache key:
// dns:cache:{tenant}:{ecs|"g"}:{qname}:{qtype}
func CacheKey(tenantID, ecs, qname, qtype string) string {
	if ecs == "" {
		ecs = "g" // global (no ECS scope)
	}
	return fmt.Sprintf("dns:cache:%s:%s:%s:%s", Safe(tenantID), Safe(ecs), Safe(strings.ToLower(qname)), qtype)
}

func ECSActiveSetKey(tenantID string) string { return "dns:ecs:" + Safe(tenantID) }

// Safe sanitizes a value for use inside a Redis key: it keeps only
// [a-zA-Z0-9._/-] and caps length, which prevents key injection through
// crafted qnames/ECSs.
func Safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == '/' {
			b.WriteRune(r)
		}
		if b.Len() >= 120 {
			break
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func PackMsg(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
func UnpackMsg(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
