package dnsx

import (
	"net"
	"testing"
)

func TestClampScope(t *testing.T) {
	// 客户端 /32 → 收敛到 /24
	e := &ECSInfo{Family: 1, Source: 32, Address: net.IPv4(1, 2, 3, 4), HasOption: true}
	e.clampScope(24)
	if e.Source != 24 || e.Address.String() != "1.2.3.0" {
		t.Fatalf("clamp /32 -> /24: got %s/%d", e.Address, e.Source)
	}

	// 已比 max 粗的不应再收敛
	e2 := &ECSInfo{Family: 1, Source: 16, Address: net.IPv4(1, 2, 3, 4), HasOption: true}
	e2.clampScope(24)
	if e2.Source != 16 {
		t.Fatalf("/16 should stay, got /%d", e2.Source)
	}

	// IPv6 不受 0..32 约束
	e3 := &ECSInfo{Family: 2, Source: 56, Address: net.ParseIP("2001:db8::1"), HasOption: true}
	e3.clampScope(24)
	if e3.Source != 56 {
		t.Fatalf("IPv6 should be unaffected, got /%d", e3.Source)
	}
}
