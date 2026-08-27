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
	db, _ := sql.Open("mysql", dsn)
	defer db.Close()
	var id int64
	var ts, aid, an, action, target, det, cip, ph, eh, ver sql.NullString
	db.QueryRow(`SELECT id, DATE_FORMAT(ts, '%Y-%m-%d %H:%i:%s.%f'), actor_id, actor_name, action, target, CAST(detail AS CHAR), client_ip, prev_hash, entry_hash, verifier FROM audit_logs WHERE id=44`).
		Scan(&id, &ts, &aid, &an, &action, &target, &det, &cip, &ph, &eh, &ver)
	fmt.Printf("id=%d\n", id)
	fmt.Printf("ts=%q\n", ts.String)
	fmt.Printf("aid=%q an=%q action=%q target=%q\n", aid.String, an.String, action.String, target.String)
	fmt.Printf("det=%q cip=%q ver=%q\n", det.String, cip.String, ver.String)
	fmt.Printf("prev=%q\n", ph.String)
	calc := auditHash(ph.String, ts.String, aid.String, an.String, action.String, target.String, det.String, cip.String, ver.String)
	fmt.Printf("calc=%s\n", calc)
	fmt.Printf("db  =%s\n", eh.String)
}
