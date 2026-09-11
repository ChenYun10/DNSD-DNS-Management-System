package threatintel

import "testing"

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
