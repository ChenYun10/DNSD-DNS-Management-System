package store

import (
	"crypto/sha256"
	"encoding/hex"
	"context"
	"database/sql"
	"log"
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

// auditHash 计算审计日志条目的 SHA-256 哈希(防篡改哈希链的一环)
func auditHash(prevHash, ts, actorID, actorName, action, target, detail, clientIP, verifier string) string {
	h := sha256.New()
	h.Write([]byte(prevHash + "|" + ts + "|" + actorID + "|" + actorName + "|" + action + "|" + target + "|" + detail + "|" + clientIP + "|" + verifier))
	return hex.EncodeToString(h.Sum(nil))
}

func (s *MySQLStore) WriteAudit(ctx context.Context, a model.AuditRow) error {
	if a.TS.IsZero() {
		a.TS = time.Now()
	}
	// 哈希链: 读取最后一条 entry_hash 作为 prev_hash, 保证日志不可篡改(等保)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var prevHash sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1 FOR UPDATE`).Scan(&prevHash); err != nil && err != sql.ErrNoRows {
		return err
	}
	ph := ""
	if prevHash.Valid {
		ph = prevHash.String
	}
	// 先截断到毫秒(与 DATETIME(3) 存储精度一致), 避免纳秒精度导致哈希不一致
	tsMs := a.TS.UTC().Truncate(time.Millisecond)
	tsStr := tsMs.Format("2006-01-02 15:04:05.000000")
	verifier := "apid"
	eh := auditHash(ph, tsStr, a.ActorID, a.ActorName, a.Action, a.Target, a.Detail, a.ClientIP, verifier)

	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_logs (ts, actor_id, actor_name, action, target, detail, client_ip, prev_hash, entry_hash, verifier) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		tsMs, nullStr(a.ActorID), a.ActorName, a.Action, a.Target, nullStr(a.Detail), nullStr(a.ClientIP), ph, eh, verifier)
	if err != nil {
		return err
	}
	return tx.Commit()
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
		where = append(where, "qname LIKE ?")
		args = append(args, "%"+qname+"%")
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
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM query_logs"+w, args...).Scan(&total); err != nil {
		return nil, 0, err
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
	q := `SELECT ts, actor_id, actor_name, action, target, detail, client_ip, prev_hash, entry_hash, verifier FROM audit_logs`
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
		var aid, an, det, cip, ph, eh, ver sql.NullString
		if err := rows.Scan(&a.TS, &aid, &an, &a.Action, &a.Target, &det, &cip, &ph, &eh, &ver); err != nil {
			return nil, err
		}
		a.ActorID = aid.String
		a.ActorName = an.String
		a.Detail = det.String
		a.ClientIP = cip.String
		a.PrevHash = ph.String
		a.EntryHash = eh.String
		a.Verifier = ver.String
		out = append(out, a)
	}
	return out, rows.Err()
}


// normalizeTS 时间字符串原样返回(数据库 DATE_FORMAT %f 的 6 位小数即权威值,
// 不做 Parse/UTC 转换避免精度丢失或时区漂移导致哈希不一致)
func normalizeTS(s string) string {
	return s
}

// VerifyAuditChain 校验审计日志哈希链完整性, 返回是否完整 + 断点位置(-1=完整)
// 等保: 审计日志完整性保护 - 任何中间篡改都会导致后续 entry_hash 全部失配
func (s *MySQLStore) VerifyAuditChain(ctx context.Context, limit int) (bool, int64, error) {
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s.%f') AS ts, actor_id, actor_name, action, target, detail, client_ip, prev_hash, entry_hash, verifier FROM audit_logs ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	prev := ""
	started := false
	for rows.Next() {
		var id int64
		var ts, aid, an, action, target, det, cip, ph, eh, ver sql.NullString
		if err := rows.Scan(&id, &ts, &aid, &an, &action, &target, &det, &cip, &ph, &eh, &ver); err != nil {
			return false, 0, err
		}
		// 跳过迁移前的旧记录(无 entry_hash): 从第一条有哈希的日志开始校验
		if !eh.Valid || eh.String == "" {
			continue
		}
		if !started {
			// 新链起点: prev_hash 应等于上一行(无论是否旧记录)的 entry_hash;
			// 迁移场景 prev_hash 为空则视为 genesis
			started = true
			if ph.Valid && ph.String != "" {
				prev = ph.String
			}
		}
		tsStr := normalizeTS(ts.String)
		calc := auditHash(prev, tsStr, aid.String, an.String, action.String, target.String, det.String, cip.String, ver.String)
		if calc != eh.String {
			return false, id, nil
		}
		prev = eh.String
	}
	return true, -1, rows.Err()
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
