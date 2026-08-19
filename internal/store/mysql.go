package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// MySQLStore wraps the metadata + logging database.
type MySQLStore struct {
	db *sql.DB
}

func NewMySQLStore(dsn string) (*MySQLStore, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql open: %w", err)
	}
	db.SetMaxOpenConns(64)
	db.SetMaxIdleConns(16)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("mysql ping: %w", err)
	}
	return &MySQLStore{db: db}, nil
}

func (s *MySQLStore) DB() *sql.DB { return s.db }
func (s *MySQLStore) Close() error {
	return s.db.Close()
}

// ApplySchema executes db/schema.sql (idempotent: uses CREATE TABLE IF NOT EXISTS).
func (s *MySQLStore) ApplySchema(sqlText string) error {
	// mysql driver supports multiStatements via DSN param; here we split on ";"
	// boundaries at top level (schema.sql uses simple statements).
	stmts := splitStatements(sqlText)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st); err != nil {
			return fmt.Errorf("schema exec failed for %q...: %w", truncate(st, 60), err)
		}
	}
	return nil
}

func splitStatements(sqlText string) []string {
	var out []string
	var cur []rune
	inStr := rune(0)
	for _, r := range sqlText {
		if inStr != 0 {
			cur = append(cur, r)
			if r == inStr {
				inStr = 0
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			inStr = r
			cur = append(cur, r)
		case ';':
			s := trimSpace(string(cur))
			if s != "" {
				out = append(out, s)
			}
			cur = nil
		default:
			cur = append(cur, r)
		}
	}
	if s := trimSpace(string(cur)); s != "" {
		out = append(out, s)
	}
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
