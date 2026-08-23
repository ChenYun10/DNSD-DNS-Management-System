package store

import (
	"context"
	"database/sql"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dns-platform/internal/model"
)

// QueryLogWriter buffers DNS query logs in memory and flushes them to MySQL
// in batches, so the request hot path never blocks on the database. On MySQL
// outage it keeps buffering (with a cap), drops oldest rows and logs the
// condition — the DNS service itself stays up.
type QueryLogWriter struct {
	db       *sql.DB
	ch       chan model.QueryLogRow
	batch    []model.QueryLogRow
	batchMax int
	interval time.Duration
	stdout   bool

	dropped   atomic.Int64
	flushed   atomic.Int64
	queued    atomic.Int64
	lastFlush atomic.Int64 // unix seconds
}

func NewQueryLogWriter(db *sql.DB, batchMax int, interval time.Duration) *QueryLogWriter {
	w := &QueryLogWriter{
		db:       db,
		ch:       make(chan model.QueryLogRow, 8192),
		batchMax: batchMax,
		interval: interval,
	}
	w.lastFlush.Store(time.Now().Unix())
	go w.run()
	return w
}

func (w *QueryLogWriter) Write(row model.QueryLogRow) {
	if row.TS.IsZero() {
		row.TS = time.Now()
	}
	select {
	case w.ch <- row:
		w.queued.Add(1)
	default:
		// buffer full — drop oldest, never block the DNS path
		w.dropped.Add(1)
		select {
		case <-w.ch:
		default:
		}
		select {
		case w.ch <- row:
			w.queued.Add(1)
		default:
			w.dropped.Add(1)
		}
	}
}

func (w *QueryLogWriter) Stats() (flushed, queued, dropped int64) {
	return w.flushed.Load(), w.queued.Load(), w.dropped.Load()
}

func (w *QueryLogWriter) run() {
	if w.stdout {
		// dev-only: print rows directly to stdout
		for row := range w.ch {
			log.Printf("[querylog] %s tenant=%s ip=%s ecs=%s %s %s rcode=%s hit=%v up=%s/%s rtt=%dms dnssec=%v via=%s",
				row.TS.Format("2006-01-02T15:04:05.000"), row.TenantID, row.ClientIP, row.ECS,
				row.QName, row.QType, row.RCode, row.CacheHit, row.UpstreamGrp, row.Upstream,
				row.RTTMS, row.DNSSECOK, row.Via)
		}
		return
	}
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case row := <-w.ch:
			w.batch = append(w.batch, row)
			if len(w.batch) >= w.batchMax {
				w.flush()
			}
		case <-ticker.C:
			if len(w.batch) > 0 {
				w.flush()
			}
		}
	}
}

func (w *QueryLogWriter) flush() {
	if len(w.batch) == 0 {
		return
	}
	batch := w.batch
	w.batch = nil
	if err := w.insert(batch); err != nil {
		// requeue at the head (bounded)
		w.dropped.Add(int64(len(batch)))
		log.Printf("[querylog] mysql flush error: %v (dropped %d rows)", err, len(batch))
	}
}

const qlInsert = `INSERT INTO query_logs
 (ts, tenant_id, client_ip, ecs, qname, qtype, rcode, cache_hit, upstream_group, upstream, rtt_ms, dnssec_ok, vip, via)
 VALUES `

func (w *QueryLogWriter) insert(rows []model.QueryLogRow) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, qlInsert+"(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for i := range rows {
		r := &rows[i]
		if _, err := stmt.ExecContext(ctx,
			r.TS, nullStr(r.TenantID), r.ClientIP, nullStr(r.ECS), r.QName, r.QType, r.RCode,
			r.CacheHit, nullStr(r.UpstreamGrp), nullStr(r.Upstream), r.RTTMS, r.DNSSECOK, r.VIP, r.Via,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	w.flushed.Add(int64(len(rows)))
	w.lastFlush.Store(time.Now().Unix())
	return nil
}

// ---------------------------------------------------------------------------
// Audit log (admin/management actions)
// ---------------------------------------------------------------------------

func (s *MySQLStore) WriteAudit(ctx context.Context, a model.AuditRow) error {
	if a.TS.IsZero() {
		a.TS = time.Now()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_logs (ts, actor_id, actor_name, action, target, detail, client_ip) VALUES (?,?,?,?,?,?,?)`,
		a.TS, nullStr(a.ActorID), a.ActorName, a.Action, a.Target, nullStr(a.Detail), nullStr(a.ClientIP))
	return err
}

// countCache memoizes COUNT(*) results for a few seconds.
// The logs page polls every few seconds; without this, each poll runs a
// multi-million-row index scan (table grows ~8.6M rows/day) and the page
// takes 4-8s per click. A short TTL is fine for pagination UI totals.
type countCache struct {
	mu sync.Mutex
	m  map[string]cachedCount
}

type cachedCount struct {
	total int64
	exp   time.Time
}

var queryCountCache = &countCache{m: make(map[string]cachedCount)}

func (c *countCache) get(key string) (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	if !ok || time.Now().After(v.exp) {
		if ok {
			delete(c.m, key)
		}
		return 0, false
	}
	return v.total, true
}

func (c *countCache) put(key string, total int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = cachedCount{total: total, exp: time.Now().Add(10 * time.Second)}
	// bound the map: opportunistically drop expired entries
	if len(c.m) > 256 {
		for k, v := range c.m {
			if time.Now().After(v.exp) {
				delete(c.m, k)
			}
		}
	}
}

// QueryLogs returns paged query logs with optional filters (all parameters
// are bound, never concatenated — no SQL injection surface).
func (s *MySQLStore) QueryLogs(ctx context.Context, tenantID, qname, qtype, from, to string, limit, offset int) ([]model.QueryLogRow, int64, error) {
	where := []string{"1=1"}
	args := []any{}
	if tenantID != "" {
		where = append(where, "tenant_id = ?")
		args = append(args, tenantID)
	}
	if qname != "" {
		// 后缀匹配(rev_qname 虚拟列索引):避免前导 % 导致索引失效
		where = append(where, "rev_qname LIKE ?")
		args = append(args, reverseStr(qname)+"%")
	}
	if qtype != "" {
		where = append(where, "qtype = ?")
		args = append(args, qtype)
	}
	if from != "" {
		where = append(where, "ts >= ?")
		args = append(args, from)
	}
	if to != "" {
		where = append(where, "ts <= ?")
		args = append(args, to)
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	w := " WHERE " + joinWhere(where)
	// COUNT cache: same WHERE+args ⇒ same key. All args here are strings.
	var key strings.Builder
	key.WriteString(w)
	for _, a := range args {
		key.WriteString("|")
		key.WriteString(a.(string))
	}
	var total int64
	if cached, ok := queryCountCache.get(key.String()); ok {
		total = cached
	} else {
		// 封顶 COUNT:表已数千万行规模,精确 COUNT 要扫整个索引(数秒~十几秒)。
		// MariaDB LIMIT ROWS EXAMINED 让扫描在检查 cap 行后停止——
		// 分页 UI 只需要“还有没有更多”,超过 10000 条返回 10000 足够。
		const maxCountRows = 10001
		countQ := "SELECT COUNT(*) FROM query_logs" + w + " LIMIT ROWS EXAMINED " + strconv.Itoa(maxCountRows)
		if err := s.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		queryCountCache.put(key.String(), total)
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT ts, tenant_id, client_ip, ecs, qname, qtype, rcode, cache_hit, upstream_group, upstream, rtt_ms, dnssec_ok, vip, via FROM query_logs"+w+
			" ORDER BY ts DESC LIMIT ? OFFSET ?", append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []model.QueryLogRow
	for rows.Next() {
		var r model.QueryLogRow
		var tid, ecs, ug, up sql.NullString
		if err := rows.Scan(&r.TS, &tid, &r.ClientIP, &ecs, &r.QName, &r.QType, &r.RCode, &r.CacheHit, &ug, &up, &r.RTTMS, &r.DNSSECOK, &r.VIP, &r.Via); err != nil {
			return nil, 0, err
		}
		r.TenantID = tid.String
		r.ECS = ecs.String
		r.UpstreamGrp = ug.String
		r.Upstream = up.String
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// QueryAudit returns recent audit log rows (admin channel).
func (s *MySQLStore) QueryAudit(ctx context.Context, action string, limit int) ([]model.AuditRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q := `SELECT ts, actor_id, actor_name, action, target, detail, client_ip FROM audit_logs`
	args := []any{}
	if action != "" {
		q += ` WHERE action = ?`
		args = append(args, action)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditRow
	for rows.Next() {
		var a model.AuditRow
		var aid, an, det, cip sql.NullString
		if err := rows.Scan(&a.TS, &aid, &an, &a.Action, &a.Target, &det, &cip); err != nil {
			return nil, err
		}
		a.ActorID = aid.String
		a.ActorName = an.String
		a.Detail = det.String
		a.ClientIP = cip.String
		out = append(out, a)
	}
	return out, rows.Err()
}

func joinWhere(parts []string) string {
	out := ""
	for i, p := range parts {
		if i == 0 {
			out = p
		} else {
			out += " AND " + p
		}
	}
	return out
}

// reverseStr reverses a string (for REVERSE(qname) indexed lookup).
func reverseStr(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
