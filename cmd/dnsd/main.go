// dnsd is the DNS data-plane daemon: UDP/TCP (53), DoT (853), DoH (8443),
// DoQ (784). It never touches MySQL on the request path — Redis is the cache,
// and query logs are pushed to MySQL asynchronously by the API daemon's
// writer (or here when built together; see -log flag).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/dnsx"
	"dns-platform/internal/store"
)

// newRedisClient builds the shared redis client used for rate limits, ECS
// tracking, JWT state and hot-domain sets (the DNS answer cache uses its own
// pooled client from store.NewRedisCache).
func newRedisClient(cfg *config.Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
		PoolSize: 64,
	})
}

func main() {
	envFile := flag.String("env", ".env", "path to .env file (optional)")
	flag.Parse()

	cfg, err := config.Load(*envFile)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// --- cache (Redis in prod; memory only for dev smoke tests) ---
	var cache store.Cache
	var rdb = newRedisClient(cfg)
	if cfg.CacheDriver == "redis" {
		c, err := store.NewRedisCache(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
		if err != nil {
			log.Fatalf("redis: %v", err)
		}
		cache = c
	} else {
		cache = store.NewMemoryCache()
		log.Printf("[warn] CACHE_DRIVER=memory — dev only")
	}

	// --- metadata repos (MySQL) ---
	mysql, err := store.NewMySQLStore(cfg.MySQLDSN)
	if err != nil {
		log.Fatalf("mysql: %v", err)
	}
	repos := store.NewRepos(mysql.DB(), rdb)

	// --- query logger: async MySQL batch writer (LOG_DRIVER=stdout for dev) ---
	var qlw *store.QueryLogWriter
	if cfg.LogDriver == "mysql" {
		qlw = store.NewQueryLogWriter(mysql.DB(), cfg.LogBatchSize, cfg.LogFlushInterval)
	} else {
		qlw = store.NewStdoutLogWriter()
		log.Printf("[warn] LOG_DRIVER=stdout — dev only")
	}

	// --- core pipeline ---
	core := dnsx.NewCore(cfg, cache, qlw, repos, rdb)
	if err := core.ReloadAll(context.Background()); err != nil {
		log.Printf("[warn] initial reload failed (is MySQL seeded?): %v", err)
	}
	core.UpstreamManager().StartHealthChecks()

	// --- live stats ? Redis (consumed by the API daemon's overview) ---
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		ctx := context.Background()
		for range t.C {
			qps, hitRate, errRate := core.Stats().Snapshot()
			tq, th, te := core.Stats().Totals()
			hitTotal := 0.0
			errTotal := 0.0
			if tq > 0 {
				hitTotal = float64(th) / float64(tq) * 100.0
				errTotal = float64(te) / float64(tq) * 100.0
			}
			payload, err := json.Marshal(map[string]any{
				"instance_id":           cfg.InstanceID,
				"qps":                   qps,
				"hit_rate_pct":          hitRate,
				"error_rate_pct":        errRate,
				"hit_rate_total_pct":    hitTotal,
				"error_rate_total_pct":  errTotal,
				"total_queries":         tq,
				"total_hits":            th,
				"total_errors":          te,
				"ts":                    time.Now().Unix(),
			})
			if err != nil {
				continue
			}
			if err := rdb.Set(ctx, "dns:stats:overview", payload, 15*time.Second).Err(); err != nil {
				log.Printf("[stats] redis push failed: %v", err)
			}
		}
	}()

	// --- listeners ---
	srv, err := dnsx.NewServer(cfg, core)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	log.Printf("[dnsd] instance=%s ENV=%s base_domain=%s dnssec=%s ecs=%v", cfg.InstanceID, cfg.Env, cfg.BaseDomain, cfg.DNSSECMode, cfg.ECSPassthrough)

	// --- config hot-reload: poll the version key bumped by the API daemon ---
	go func() {
		ctx := context.Background()
		last := int64(-1)
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			v, err := rdb.Get(ctx, "dns:config:version").Int64()
			if err != nil {
				continue
			}
			if v != last {
				if err := core.ReloadAll(ctx); err != nil {
					log.Printf("[config] reload failed: %v", err)
				} else {
					last = v
					log.Printf("[config] hot reload applied (version %d)", v)
				}
			}
		}
	}()

	// --- graceful shutdown ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("[dnsd] shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	core.UpstreamManager().Close()
	cache.Close()
	mysql.Close()
}
