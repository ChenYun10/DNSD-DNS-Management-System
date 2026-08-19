package dnsx

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"dns-platform/internal/store"
)

// Limiter is a token-bucket style rate limiter:
//   - DNS plane: per (tenant, client IP) QPS caps, Redis-backed so it works
//     across instances. VIP tenants get a multiplier (高价值专用通道).
//   - Login plane: per-IP failed-login caps (brute-force protection).
type Limiter struct {
	rdb    *redis.Client
	mem    *store.MemoryCache // dev fallback counter store
	qps    int
	vipMul int

	mu   sync.Mutex
	mem2 map[string]*memCounter
}

type memCounter struct {
	count int64
	at    time.Time
}

func NewLimiter(rdb *redis.Client, qps, vipMul int) *Limiter {
	return &Limiter{rdb: rdb, qps: qps, vipMul: vipMul, mem2: make(map[string]*memCounter)}
}

func (l *Limiter) redisOK() bool { return l.rdb != nil }

// AllowDNS checks whether (tenant, clientIP) may issue a query now.
func (l *Limiter) AllowDNS(ctx context.Context, tenantID, clientIP string, vip bool) bool {
	limit := l.qps
	if vip && l.vipMul > 0 {
		limit = l.qps * l.vipMul
	}
	key := fmt.Sprintf("dns:rate:%s:%s:%d", store.Safe(tenantID), store.Safe(clientIP), time.Now().Unix())
	if l.redisOK() {
		n, err := l.rdb.Incr(ctx, key).Result()
		if err == nil {
			if n == 1 {
				l.rdb.Expire(ctx, key, 2*time.Second)
			}
			return n <= int64(limit)
		}
		// redis hiccup: fall through to memory (fail-open with memory cap)
	}
	return l.memAllow("dns", key, limit)
}

// AllowLogin caps failed login attempts per IP within a window.
func (l *Limiter) AllowLogin(ctx context.Context, clientIP string, limit int, window time.Duration) bool {
	key := fmt.Sprintf("dns:rate:login:%s:%d", store.Safe(clientIP), time.Now().Unix()/int64(window.Seconds()))
	if l.redisOK() {
		n, err := l.rdb.Incr(ctx, key).Result()
		if err == nil {
			if n == 1 {
				l.rdb.Expire(ctx, key, window+5*time.Second)
			}
			return n <= int64(limit)
		}
	}
	return l.memAllow("login", key, limit)
}

func (l *Limiter) memAllow(prefix, key string, limit int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.mem2[key]
	if !ok || time.Since(c.at) > 2*time.Second {
		l.mem2[key] = &memCounter{count: 1, at: time.Now()}
		if len(l.mem2) > 100000 {
			l.mem2 = map[string]*memCounter{}
		}
		return 1 <= int64(limit)
	}
	c.count++
	return c.count <= int64(limit)
}

// ResetLogin resets the login counter for an IP after a successful login.
func (l *Limiter) ResetLogin(ctx context.Context, clientIP string) {
	if l.redisOK() {
		iter := l.rdb.Scan(ctx, 0, "dns:rate:login:"+store.Safe(clientIP)+":*", 100).Iterator()
		for iter.Next(ctx) {
			l.rdb.Del(ctx, iter.Val())
		}
	}
}
