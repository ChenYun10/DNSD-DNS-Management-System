package api

import (
	"context"
	"net/http"
	"time"

	"dns-platform/internal/store"
)

// --- cache management (Redis 缓存管理) ---

func (a *API) cacheStats(w http.ResponseWriter, r *http.Request) {
	flushed, queued, dropped := int64(0), int64(0), int64(0)
	if a.logger != nil {
		flushed, queued, dropped = a.logger.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cache_driver": a.cfg.CacheDriver,
		"log_flushed":  flushed,
		"log_queued":   queued,
		"log_dropped":  dropped,
		"active_ecs":   a.activeECSCount(r.Context()),
		"dnssec_ok":    a.dnssecStats(),
	})
}

func (a *API) activeECSCount(ctx context.Context) int64 {
	if a.rdb == nil {
		return 0
	}
	var total int64
	iter := a.rdb.Scan(ctx, 0, "dns:ecs:*", 200).Iterator()
	for iter.Next(ctx) {
		n, _ := a.rdb.SCard(ctx, iter.Val()).Result()
		total += n
	}
	return total
}

func (a *API) dnssecStats() map[string]uint64 {
	ok, fail := a.core.DNSSECStats()
	return map[string]uint64{"verified": ok, "failed": fail}
}

func (a *API) cachePurge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TenantID string `json:"tenant_id"`
		QName    string `json:"qname"`
		ECS      string `json:"ecs"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	prefix := "dns:cache:"
	if in.TenantID != "" {
		prefix += store.Safe(in.TenantID)
		if in.ECS != "" {
			prefix += ":" + store.Safe(in.ECS)
		}
		if in.QName != "" {
			prefix += ":" + store.Safe(in.QName)
		}
	}
	n, err := a.core.CacheDriver().Purge(r.Context(), prefix)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAction(r, "cache.purge", prefix, map[string]any{"deleted": n})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": n})
}

// cacheWarm starts a custom warmup job: domains × ECS list (from body, or the
// tenant's active ECS set when omitted) — 动态预热.
func (a *API) cacheWarm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		TenantID string   `json:"tenant_id"`
		Domains  []string `json:"domains"`
		ECS      []string `json:"ecs"`
	}
	if err := readJSON(w, r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if in.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "tenant_id required")
		return
	}
	if len(in.Domains) == 0 {
		writeErr(w, http.StatusBadRequest, "domains required")
		return
	}
	if len(in.Domains) > 200 {
		writeErr(w, http.StatusBadRequest, "max 200 domains per job")
		return
	}
	job, err := a.core.Warmup().Warm(r.Context(), in.TenantID, in.Domains, in.ECS)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditAction(r, "cache.warm", "tenant:"+in.TenantID, map[string]any{"job": job.ID, "domains": len(in.Domains), "ecs": len(job.ECSs)})
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) warmJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.core.Warmup().Jobs())
}

var _ = time.Now
