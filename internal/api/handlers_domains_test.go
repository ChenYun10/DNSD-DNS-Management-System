package api

import "testing"

func TestValidDomain(t *testing.T) {
	cases := map[string]bool{
		"dns.customer.com":       true,
		"example.com":            true,
		"sub-domain.example.com": true,
		"xn--fsq.com":            true, // punycode
		"a1.example.com":         true,
		"":                       false,
		"..":                     false,
		"../etc/passwd":          false,
		"example.com/../../x":    false,
		"example.com\\..\\x":     false,
		"*.example.com":          false,
		"bad_domain.com":         false,
		"-bad.com":               false,
		"bad-.com":               false,
		"a b.com":                false,
		"UPPER.com":              false,
		"a..b.com":               false,
	}
	for in, want := range cases {
		if got := validDomain(in); got != want {
			t.Fatalf("validDomain(%q)=%v, want %v", in, got, want)
		}
	}
}
