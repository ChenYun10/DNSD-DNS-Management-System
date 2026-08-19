package store

import (
	"dns-platform/internal/model"
)

// NewStdoutLogWriter returns a dev-only query log writer that prints rows to
// stdout instead of MySQL. Never used when ENV=prod (config forbids it).
func NewStdoutLogWriter() *QueryLogWriter {
	return &QueryLogWriter{
		ch:     make(chan model.QueryLogRow, 8192),
		stdout: true,
	}
}
