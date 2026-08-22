package dnsx

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"dns-platform/internal/config"
	"dns-platform/internal/store"
)

// WarmupManager implements 动态预热:
//  1. Active-ECS tracking — every query records its ECS into a Redis set
//     per tenant, so we always know which subnets are "live". The tracking
//     writes are batched (channel + flusher) so the request hot path never
//     pays a Redis round-trip for SADD/EXPIRE.
//  2. On-demand warming (API): warm(domains × active ECS) through the real
//     upstream pipeline, writing results into the Redis cache.
//  3. Adaptive warming (cache layer): hot entries near expiry are refreshed
//     asynchronously before clients ever see a miss.
type WarmupManager struct {
	cfg  *config.Config
	rdb  *redis.Client
	core *Core // back-reference for upstream exchange

	mu   sync.Mutex
	jobs map[string]*WarmJob

	ecsCh    chan ecsTrack
	stopCh   chan struct{}
	stopOnce sync.Once
}

type ecsTrack struct {
	tenantID string
	ecs      string
}

type WarmJob struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Domains   []string  `json:"domains"`
	ECSs      []string  `json:"ecs_list"`
	Total     int       `json:"total"`
	Done      int       `json:"done"`
	Failed    int       `json:"failed"`
	StartedAt time.Time `json:"started_at"`
	Finished  bool      `json:"finished"`
	Error     string    `json:"error,omitempty"`
}

func NewWarmupManager(cfg *config.Config, rdb *redis.Client, core *Core) *WarmupManager {
	return &WarmupManager{
		cfg: cfg, rdb: rdb, core: core, jobs: make(map[string]*WarmJob),
		ecsCh:  make(chan ecsTrack, 8192),
		stopCh: make(chan struct{}),
	}
}

// Start launches the batched ECS-tracking flusher.
func (w *WarmupManager) Start() {
	go w.ecsFlusher()
}

// Stop flushes pending ECS tracking and stops the flusher goroutine.
func (w *WarmupManager) Stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
}

// TrackActiveECS records the ECS subnet seen for a tenant. It is called on
// every query but only does a non-blocking channel send; the flusher batches
// SADD+EXPIRE into Redis pipelines. Drops silently when the buffer is full.
func (w *WarmupManager) TrackActiveECS(ctx context.Context, tenantID, ecs string) {
	if w.rdb == nil || tenantID == "" || ecs == "" {
		return
	}
	select {
	case w.ecsCh <- ecsTrack{tenantID: tenantID, ecs: ecs}:
	default: // buffer full — drop; next tracking round will re-add
	}
}

// ecsFlusher drains the tracking channel in batches: one Redis Pipeline per
// flush, so N queries cost ~1 round-trip per 2s instead of 2 per query.
func (w *WarmupManager) ecsFlusher() {
	pending := map[string]map[string]bool{} // tenantID -> set(ecs)
	count := func() int {
		n := 0
		for _, s := range pending {
			n += len(s)
		}
		return n
	}
	flush := func() {
		if len(pending) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		pipe := w.rdb.Pipeline()
		for tid, ecss := range pending {
			key := store.ECSActiveSetKey(tid)
			args := make([]any, 0, len(ecss))
			for e := range ecss {
				args = append(args, e)
			}
			pipe.SAdd(ctx, key, args...)
			pipe.Expire(ctx, key, 7*24*time.Hour)
		}
		pipe.Exec(ctx)
		pending = map[string]map[string]bool{}
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case tr := <-w.ecsCh:
			if pending[tr.tenantID] == nil {
				pending[tr.tenantID] = map[string]bool{}
			}
			pending[tr.tenantID][tr.ecs] = true
			if count() >= 500 {
				flush()
			}
		case <-t.C:
			flush()
		case <-w.stopCh:
			flush()
			return
		}
	}
}

// ActiveECS returns the recently-seen subnets for a tenant.
func (w *WarmupManager) ActiveECS(ctx context.Context, tenantID string) []string {
	if w.rdb == nil {
		return nil
	}
	members, err := w.rdb.SMembers(ctx, store.ECSActiveSetKey(tenantID)).Result()
	if err != nil {
		return nil
	}
	sort.Strings(members)
	return members
}

// Warm starts an asynchronous warming job: for each domain × ECS, it fetches
// through the upstream pipeline (bypassing cache reads, writing cache writes).
func (w *WarmupManager) Warm(ctx context.Context, tenantID string, domains []string, ecsList []string) (*WarmJob, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains required")
	}
	if len(ecsList) == 0 {
		ecsList = w.ActiveECS(ctx, tenantID)
	}
	if len(ecsList) == 0 {
		ecsList = []string{""} // warm the global (no-ECS) entries too
	}
	job := &WarmJob{
		ID:        uuid.NewString(),
		TenantID:  tenantID,
		Domains:   domains,
		ECSs:      ecsList,
		Total:     len(domains) * len(ecsList),
		StartedAt: time.Now(),
	}
	w.mu.Lock()
	w.jobs[job.ID] = job
	w.mu.Unlock()

	// persist status to Redis for cross-instance visibility
	if w.rdb != nil {
		w.rdb.HSet(ctx, "dns:warm:"+job.ID, "status", "running", "total", job.Total)
		w.rdb.Expire(ctx, "dns:warm:"+job.ID, 24*time.Hour)
	}

	go w.run(ctx, job)
	return job, nil
}

func (w *WarmupManager) run(ctx context.Context, job *WarmJob) {
	sem := make(chan struct{}, w.cfg.WarmupConcurrency)
	var wg sync.WaitGroup
	for _, d := range job.Domains {
		for _, ecs := range job.ECSs {
			wg.Add(1)
			sem <- struct{}{}
			go func(domain, ecsStr string) {
				defer wg.Done()
				defer func() { <-sem }()
				if err := w.warmOne(ctx, job.TenantID, domain, ecsStr); err != nil {
					job.Failed++
				}
				job.Done++
			}(d, ecs)
		}
	}
	wg.Wait()
	job.Finished = true
	if w.rdb != nil {
		w.rdb.HSet(ctx, "dns:warm:"+job.ID, "status", "done", "done", job.Done, "failed", job.Failed)
	}
	w.mu.Lock()
	// keep the job object for status queries; prune old finished jobs
	for id, j := range w.jobs {
		if j.Finished && time.Since(j.StartedAt) > time.Hour {
			delete(w.jobs, id)
		}
	}
	w.mu.Unlock()
	log.Printf("[warmup] job %s finished: %d/%d ok, %d failed", job.ID, job.Done-job.Failed, job.Total, job.Failed)
}

// warmOne performs a single cache-bypass upstream fetch and stores the result.
func (w *WarmupManager) warmOne(ctx context.Context, tenantID, qname, ecsStr string) error {
	tenant, err := w.core.repos.GetTenant(ctx, tenantID)
	if err != nil || tenant == nil {
		return fmt.Errorf("tenant lookup: %w", err)
	}
	ecs, err := parseECSFromString(ecsStr)
	if err != nil {
		return err
	}
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	req.SetEdns0(1232, false)
	if ecs != nil {
		req = attachECS(req, ecs)
	}
	_, err = w.core.fetchAndCache(ctx, tenant, req, ecs, nil, "warmup")
	return err
}

// Jobs returns snapshots of running/finished warmup jobs.
func (w *WarmupManager) Jobs() []*WarmJob {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*WarmJob, 0, len(w.jobs))
	for _, j := range w.jobs {
		cp := *j
		cp.Domains = append([]string(nil), j.Domains...)
		cp.ECSs = append([]string(nil), j.ECSs...)
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

// isHotDomain reports whether a qname belongs to the tenant's hot list
// (used by adaptive warming).
//
// Deprecated: replaced by Core.isHotDomainLocal (in-memory hot set, no Redis
// round-trip per query). Kept as a pure helper for reference.
func isHotDomain(rdb *redis.Client, tenantID, qname string) bool {
	if rdb == nil {
		return false
	}
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	ok, err := rdb.SIsMember(context.Background(), "dns:hot:"+store.Safe(tenantID), q).Result()
	if err == nil && ok {
		return true
	}
	parts := strings.Split(q, ".")
	for i := 1; i < len(parts)-1; i++ {
		suffix := strings.Join(parts[i:], ".")
		ok, err := rdb.SIsMember(context.Background(), "dns:hot:"+store.Safe(tenantID), suffix).Result()
		if err == nil && ok {
			return true
		}
	}
	return false
}
