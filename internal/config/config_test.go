package config

import "testing"

func TestIsPlaceholderSecret(t *testing.T) {
	cases := map[string]bool{
		"CHANGE_ME_TO_A_RANDOM_64_HEX_STRING": true,
		"CHANGE_ME_BOOTSTRAP":                 true,
		"changeme":                            true,
		"your_secret_here":                    true,
		"example-secret":                      true,
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6":    false, // 真实随机 hex
		"9f8e7d6c5b4a39281706f5e4d3c2b1a0":    false,
	}
	for in, want := range cases {
		if got := isPlaceholderSecret(in); got != want {
			t.Fatalf("isPlaceholderSecret(%q)=%v, want %v", in, got, want)
		}
	}
}
