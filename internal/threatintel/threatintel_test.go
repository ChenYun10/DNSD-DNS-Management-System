package threatintel

import (
	"net"
	"testing"

	"dns-platform/internal/config"
)

func TestBlacklistMatch(t *testing.T) {
	b := &blacklist{
		exact:    map[string]bool{"evil.com": true},
		wildcard: []string{".ads.example.com"},
	}
	cases := []struct {
		domain string
		want   bool
	}{
		{"evil.com", true},
		{"www.evil.com", false}, // 精确匹配不含子域
		{"a.ads.example.com", true},
		{"ads.example.com", false}, // 通配符 *.ads.example.com 不含 apex
		{"good.com", false},
	}
	for _, c := range cases {
		if got := b.matches(c.domain); got != c.want {
			t.Errorf("matches(%q)=%v, want %v", c.domain, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	if normalize("Example.COM.") != "example.com" {
		t.Errorf("normalize(Example.COM.) = %q, want example.com", normalize("Example.COM."))
	}
	if normalize("") != "" {
		t.Errorf("normalize(empty) should be empty")
	}
}

func TestBlacklistEmpty(t *testing.T) {
	// nil blacklist 不匹配任何域名
	var b *blacklist
	if b.matches("evil.com") {
		t.Errorf("nil blacklist should not match")
	}
}

func TestBlockOff(t *testing.T) {
	c := NewClient(&config.Config{ThreatBlockMode: "off"})
	c.blacklist = &blacklist{exact: map[string]bool{"evil.com": true}}
	if hit, _ := c.Block("evil.com"); hit != nil {
		t.Errorf("blockMode=off should never block")
	}
}

func TestBlockBlacklist(t *testing.T) {
	c := NewClient(&config.Config{ThreatBlockMode: "127.0.0.1"})
	c.blacklist = &blacklist{exact: map[string]bool{"evil.com": true}}
	hit, ip := c.Block("evil.com")
	if hit == nil {
		t.Fatal("blacklist hit should block")
	}
	if hit.Source != "blacklist" {
		t.Errorf("source = %q, want blacklist", hit.Source)
	}
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("sinkhole = %v, want 127.0.0.1", ip)
	}
}

func TestBlockRemembered(t *testing.T) {
	c := NewClient(&config.Config{ThreatBlockMode: "127.0.0.1"})
	c.rememberBlocked("api-bad.com")
	if hit, _ := c.Block("api-bad.com"); hit == nil {
		t.Fatal("remembered (API backfilled) domain should block")
	} else if hit.Source != "api" {
		t.Errorf("source = %q, want api", hit.Source)
	}
}

func TestBlockRandom(t *testing.T) {
	c := NewClient(&config.Config{ThreatBlockMode: "random", ThreatBlockPool: "10.0.0.1,10.0.0.2"})
	c.rememberBlocked("r.com")
	_, ip := c.Block("r.com")
	if ip == nil {
		t.Fatal("random sinkhole should not be nil")
	}
	if s := ip.String(); s != "10.0.0.1" && s != "10.0.0.2" {
		t.Errorf("sinkhole = %v, want from pool", ip)
	}
}

func TestBlockCleanDomain(t *testing.T) {
	c := NewClient(&config.Config{ThreatBlockMode: "127.0.0.1"})
	c.blacklist = &blacklist{exact: map[string]bool{"evil.com": true}}
	if hit, _ := c.Block("good.com"); hit != nil {
		t.Errorf("clean domain should not block")
	}
}
