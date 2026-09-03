package store

import "testing"

func TestEscapeLike(t *testing.T) {
	cases := map[string]string{
		"example.com":   "example.com",
		"100%":          `100\%`,
		"a_b":           `a\_b`,
		`a\b`:           `a\\b`,
		`%_\`:           `\%\_\\`,
		"www.baidu.com": "www.baidu.com",
	}
	for in, want := range cases {
		if got := escapeLike(in); got != want {
			t.Fatalf("escapeLike(%q)=%q, want %q", in, got, want)
		}
	}
}
