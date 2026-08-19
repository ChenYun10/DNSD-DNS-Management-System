package dnsx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
)

// Upstream is one resolver endpoint. Implementations: UDP/TCP (traditional),
// DoT, DoH, DoQ.
type Upstream interface {
	// Exchange sends a query and returns the response.
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
	// HealthProbe checks reachability.
	HealthProbe(ctx context.Context) error
	// String identifies the upstream (protocol://name).
	String() string
}

// ---------------------------------------------------------------------------
// Manager: groups + health checks + weighted selection + failover (分流核心)
// ---------------------------------------------------------------------------

type Manager struct {
	cfg *config.Config

	mu     sync.RWMutex
	groups map[string]*GroupState
	// byName: group name -> group id (default group resolution)
	byName map[string]string
	// byTenant: tenantID -> pinned group name (VIP dedicated channel)
	byTenant map[string]string

	rrIdx map[string]*uint32 // round-robin index per group

	stop chan struct{}
}

type GroupState struct {
	model.UpstreamGroup
	Entries []*EntryState
}

type EntryState struct {
	model.Upstream
	client Upstream
	rr     *uint32 // round-robin cursor

	healthy    atomic.Bool
	consecFail atomic.Int32
	lastDown   atomic.Int64
}

// String identifies the entry for logs/UI: "protocol://address:port".
func (e *EntryState) String() string {
	if e.client != nil {
		return e.client.String()
	}
	return string(e.Protocol) + "://" + e.Address
}

func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:      cfg,
		groups:   make(map[string]*GroupState),
		byName:   make(map[string]string),
		byTenant: make(map[string]string),
		rrIdx:    make(map[string]*uint32),
		stop:     make(chan struct{}),
	}
}

// Reload rebuilds the runtime view from the repository data.
func (m *Manager) Reload(groups []*model.UpstreamGroup, upstreams []*model.Upstream, tenants []*model.Tenant) {
	m.mu.Lock()
	defer m.mu.Unlock()

	byGroup := map[string][]*model.Upstream{}
	for _, u := range upstreams {
		if !u.Enabled {
			continue
		}
		byGroup[u.GroupID] = append(byGroup[u.GroupID], u)
	}

	ng := make(map[string]*GroupState, len(groups))
	nameIdx := make(map[string]string, len(groups))
	for _, g := range groups {
		nameIdx[g.Name] = g.ID
		gs := &GroupState{UpstreamGroup: *g}
		for _, u := range byGroup[g.ID] {
			es := &EntryState{Upstream: *u}
			if idx, ok := m.rrIdx[u.ID]; ok {
				es.rr = idx
			} else {
				es.rr = new(uint32)
				m.rrIdx[u.ID] = es.rr
			}
			cl, err := buildClient(m.cfg, u)
			if err != nil {
				log.Printf("[upstream] build client for %s failed: %v", u.Name, err)
				es.healthy.Store(false)
			} else {
				es.client = cl
				es.healthy.Store(true)
			}
			gs.Entries = append(gs.Entries, es)
		}
		ng[g.ID] = gs
	}
	m.groups = ng
	m.byName = nameIdx

	mt := map[string]string{}
	for _, t := range tenants {
		if t.UpstreamGroup != "" {
			mt[t.ID] = t.UpstreamGroup
		}
	}
	m.byTenant = mt
}

// StartHealthChecks launches the periodic probe loop.
func (m *Manager) StartHealthChecks() {
	go func() {
		t := time.NewTicker(m.cfg.HealthInterval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				m.probeAll()
			}
		}
	}()
	// initial probe shortly after start
	time.AfterFunc(2*time.Second, m.probeAll)
}

// HealthSnapshot returns upstream id -> healthy for the UI.
func (m *Manager) HealthSnapshot() map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]bool)
	for _, g := range m.groups {
		for _, e := range g.Entries {
			out[e.ID] = e.healthy.Load()
		}
	}
	return out
}

func (m *Manager) probeAll() {
	m.mu.RLock()
	var entries []*EntryState
	for _, g := range m.groups {
		entries = append(entries, g.Entries...)
	}
	m.mu.RUnlock()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, es := range entries {
		if es.client == nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(es *EntryState) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), m.cfg.UpstreamTimeout)
			defer cancel()
			if err := es.client.HealthProbe(ctx); err != nil {
				fails := es.consecFail.Add(1)
				if int(fails) >= m.cfg.HealthFailsToDown {
					es.healthy.Store(false)
					es.lastDown.Store(time.Now().Unix())
					log.Printf("[upstream] %s marked UNHEALTHY (%d consecutive failures)", es.String(), fails)
				}
			} else {
				was := es.healthy.Swap(true)
				es.consecFail.Store(0)
				if !was {
					log.Printf("[upstream] %s recovered", es.String())
				}
			}
		}(es)
	}
	wg.Wait()
}

// GroupByName returns a group state by ID or name (nil when missing).
func (m *Manager) GroupByName(id string) *GroupState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if g, ok := m.groups[id]; ok {
		return g
	}
	if name, ok := m.byName[id]; ok {
		return m.groups[name]
	}
	return nil
}

// Select picks an upstream entry from a group using the group strategy.
// Unhealthy entries are skipped; if everything is unhealthy, fall back to a
// random entry (optimistic retry).
func (m *Manager) Select(g *GroupState) *EntryState {
	if g == nil || len(g.Entries) == 0 {
		return nil
	}
	var healthy []*EntryState
	for _, e := range g.Entries {
		if e.healthy.Load() && e.client != nil {
			healthy = append(healthy, e)
		}
	}
	pool := healthy
	if len(pool) == 0 {
		// everything down: optimistic fallback
		pool = g.Entries
	}
	switch g.Strategy {
	case "round_robin":
		idx := atomic.AddUint32(pool[0].rr, 1)
		return pool[int(idx)%len(pool)]
	case "failover":
		// pick the first healthy one (sorted stable)
		sort.SliceStable(pool, func(i, j int) bool { return pool[i].Weight > pool[j].Weight })
		return pool[0]
	default: // weighted random / weighted round-robin
		return weightedPick(pool)
	}
}

func weightedPick(pool []*EntryState) *EntryState {
	total := 0
	for _, e := range pool {
		total += e.Weight
	}
	if total <= 0 {
		return pool[rand.Intn(len(pool))]
	}
	r := rand.Intn(total)
	for _, e := range pool {
		r -= e.Weight
		if r < 0 {
			return e
		}
	}
	return pool[len(pool)-1]
}

// ExchangeWithFailover tries upstreams in the group until one succeeds.
// Transient errors (timeout, network, SERVFAIL when configured) trigger the
// next candidate. The chosen upstream is reported for logging.
func (m *Manager) ExchangeWithFailover(ctx context.Context, g *GroupState, msg *dns.Msg) (*dns.Msg, *EntryState, error) {
	if g == nil {
		return nil, nil, errors.New("no upstream group")
	}
	attempted := map[string]bool{}
	var lastErr error
	for i := 0; i < len(g.Entries); i++ {
		es := m.Select(g)
		if es == nil {
			break
		}
		if attempted[es.ID] {
			continue
		}
		attempted[es.ID] = true
		cctx, cancel := context.WithTimeout(ctx, timeoutFor(m.cfg, &es.Upstream))
		resp, err := es.client.Exchange(cctx, msg)
		cancel()
		if err != nil {
			lastErr = err
			es.consecFail.Add(1)
			continue
		}
		if resp.Truncated && msg.Question[0].Qtype != dns.TypeOPT {
			// retry over TCP if the first attempt was UDP
			if tcpCl, ok := es.client.(*udpClient); ok {
				if tcpResp, terr := tcpCl.exchangeTCP(ctx, msg); terr == nil {
					resp = tcpResp
				}
			}
		}
		es.consecFail.Store(0)
		es.healthy.Store(true)
		return resp, es, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no available upstream")
	}
	return nil, nil, lastErr
}

func timeoutFor(cfg *config.Config, u *model.Upstream) time.Duration {
	if u.TimeoutMS > 0 {
		return time.Duration(u.TimeoutMS) * time.Millisecond
	}
	return cfg.UpstreamTimeout
}

// buildClient constructs the protocol-specific client.
func buildClient(cfg *config.Config, u *model.Upstream) (Upstream, error) {
	addr := fmt.Sprintf("%s:%d", u.Address, u.Port)
	switch u.Protocol {
	case model.ProtoUDP, model.ProtoTCP:
		return newUDPClient(cfg, u, addr), nil
	case model.ProtoDoT:
		return newDoTClient(cfg, u, addr), nil
	case model.ProtoDoH:
		return newDoHClient(cfg, u, addr), nil
	case model.ProtoDoQ:
		return newDoQClient(cfg, u, addr), nil
	default:
		return nil, fmt.Errorf("unsupported protocol %q", u.Protocol)
	}
}

// tlsConfigForUpstream builds a hardened TLS config for upstream DoT/DoH/DoQ.
func tlsConfigForUpstream(cfg *config.Config, u *model.Upstream) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         u.Hostname,
		InsecureSkipVerify: u.TLSInsecure && cfg.Env == "dev", // never in prod
	}
}

func (m *Manager) Close() {
	close(m.stop)
}
