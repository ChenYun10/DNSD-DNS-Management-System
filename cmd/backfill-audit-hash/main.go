// backfill_audit_hash.go - recompute and backfill audit_logs hash chain
// 用法: go run ./cmd/backfill-audit-hash (需要 MYSQL_DSN 环境变量)
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"

	_ "github.com/go-sql-driver/mysql"
)

func auditHash(prevHash, ts, actorID, actorName, action, target, detail, clientIP, verifier string) string {
	h := sha256.New()
	h.Write([]byte(prevHash + "|" + ts + "|" + actorID + "|" + actorName + "|" + action + "|" + target + "|" + detail + "|" + clientIP + "|" + verifier))
	return hex.EncodeToString(h.Sum(nil))
}

func main() {
	dsn := os.Getenv("MYSQL_DSN")
	if dsn == "" {
		dsn = "dns:dns_pass@tcp(127.0.0.1:3306)/dns_platform?parseTime=true&charset=utf8mb4"
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s.%f') AS ts, actor_id, actor_name, action, target, detail, client_ip FROM audit_logs ORDER BY id ASC`)
	if err != nil {
		panic(err)
	}
	type row struct {
		id         int64
		ts         string
		actorID    sql.NullString
		actorName  sql.NullString
		action     string
		target     sql.NullString
		detail     sql.NullString
		clientIP   sql.NullString
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.ts, &r.actorID, &r.actorName, &r.action, &r.target, &r.detail, &r.clientIP); err != nil {
			panic(err)
		}
		all = append(all, r)
	}
	rows.Close()

	verifyOnly := os.Getenv("VERIFY_ONLY") == "1"
	prev := ""
	ok := true
	var firstBad int64 = -1
	for _, r := range all {
		tsStr := r.ts
		eh := auditHash(prev, tsStr, r.actorID.String, r.actorName.String, r.action, r.target.String, r.detail.String, r.clientIP.String, "apid")
		if verifyOnly {
			var existing sql.NullString
			db.QueryRow(`SELECT entry_hash FROM audit_logs WHERE id = ?`, r.id).Scan(&existing)
			if !existing.Valid || existing.String != eh {
				ok = false
				firstBad = r.id
				fmt.Printf("id=%d MISMATCH\n", r.id)
				break
			}
		} else {
			if _, err := db.Exec(`UPDATE audit_logs SET prev_hash = ?, entry_hash = ?, verifier = 'apid' WHERE id = ?`, prev, eh, r.id); err != nil {
				panic(err)
			}
			fmt.Printf("id=%d recomputed\n", r.id)
		}
		prev = eh
	}
	if verifyOnly {
		if ok {
			fmt.Println("CHAIN OK")
		} else {
			fmt.Printf("CHAIN BROKEN at id=%d\n", firstBad)
		}
	} else {
		fmt.Println("done")
	}
}
