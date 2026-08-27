// apid is the REST control-plane daemon (JWT + RBAC), fully isolated from the
// DNS data plane. It owns MySQL-backed metadata and query-log writing, plus
// Redis state (refresh tokens, rate limits, warmup status).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"dns-platform/internal/api"
	"dns-platform/internal/certmgr"
	"dns-platform/internal/config"
	"dns-platform/internal/dnsx"
	"dns-platform/internal/store"
)

func main() {
	envFile := flag.String("env", ".env", "path to .env file (optional)")
	flag.Parse()

	cfg, err := config.Load(*envFile)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// cache driver (Redis; memory only for dev)
	var cache store.Cache
	var rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB, PoolSize: 64})
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

	mysql, err := store.NewMySQLStore(cfg.MySQLDSN)
	if err != nil {
		log.Fatalf("mysql: %v", err)
	}
	repos := store.NewRepos(mysql.DB(), rdb)

	var qlw *store.QueryLogWriter
	if cfg.LogDriver == "mysql" {
		qlw = store.NewQueryLogWriter(mysql.DB(), cfg.LogBatchSize, cfg.LogFlushInterval)
	} else {
		qlw = store.NewStdoutLogWriter()
	}

	// The API daemon owns a Core instance too, so the ECS simulation /
	// warmup endpoints share the real DNS pipeline and cache.
	core := dnsx.NewCore(cfg, cache, qlw, repos, rdb)
	if err := core.ReloadAll(context.Background()); err != nil {
		log.Printf("[warn] initial reload failed (is MySQL seeded?): %v", err)
	}
	core.UpstreamManager().StartHealthChecks()

	// Admin-managed SSL: ACME issuance + renewal for tenant custom domains.
	mgr, err := certmgr.New(cfg, repos, rdb)
	if err != nil {
		log.Fatalf("certmgr: %v", err)
	}
	go mgr.RenewLoop(context.Background())

	srv := api.New(cfg, repos, mysql, qlw, core, rdb, mgr)
	if err := srv.Start(); err != nil {
		log.Fatalf("api start: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Printf("[apid] shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = ctx
	cache.Close()
	mysql.Close()
}
