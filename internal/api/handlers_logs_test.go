package api

import (
	"testing"
	"time"

	"dns-platform/internal/config"
)

func parseWindow(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.Local)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

func TestWindowBoundsDefault(t *testing.T) {
	a := &API{cfg: &config.Config{
		LogQueryDefaultWindow: 24 * time.Hour,
		LogQueryMaxWindow:     7 * 24 * time.Hour,
	}}
	from, to := a.windowBounds("", "")
	ft, tt := parseWindow(t, from), parseWindow(t, to)
	if d := tt.Sub(ft); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("default window = %v, want ~24h", d)
	}
}

func TestWindowBoundsClampMax(t *testing.T) {
	a := &API{cfg: &config.Config{
		LogQueryDefaultWindow: 24 * time.Hour,
		LogQueryMaxWindow:     48 * time.Hour,
	}}
	// 时间跨度远超上限 → 应截断到 48h
	from, to := a.windowBounds("2026-01-01 00:00:00", "2026-02-01 00:00:00")
	ft, tt := parseWindow(t, from), parseWindow(t, to)
	if d := tt.Sub(ft); d > 48*time.Hour+time.Minute {
		t.Fatalf("clamped window = %v, want <= 48h", d)
	}
}

func TestWindowBoundsSwap(t *testing.T) {
	a := &API{cfg: &config.Config{
		LogQueryDefaultWindow: 24 * time.Hour,
		LogQueryMaxWindow:     7 * 24 * time.Hour,
	}}
	from, to := a.windowBounds("2026-02-01 00:00:00", "2026-01-01 00:00:00")
	ft, tt := parseWindow(t, from), parseWindow(t, to)
	if ft.After(tt) {
		t.Fatalf("from > to after swap: %v > %v", ft, tt)
	}
}

func TestWindowBoundsNormalizeT(t *testing.T) {
	a := &API{cfg: &config.Config{
		LogQueryDefaultWindow: 24 * time.Hour,
		LogQueryMaxWindow:     7 * 24 * time.Hour,
	}}
	// 前端 datetime-local 会产生带 T 的 ISO 形式，需归一化为空格
	from, to := a.windowBounds("2026-01-01T00:00:00", "2026-01-02T00:00:00")
	ft, tt := parseWindow(t, from), parseWindow(t, to)
	if d := tt.Sub(ft); d != 24*time.Hour {
		t.Fatalf("T-normalized window = %v, want 24h", d)
	}
}
