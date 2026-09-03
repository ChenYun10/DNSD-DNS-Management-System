package dnsx

import (
	"context"
	"net"
	"testing"

	"dns-platform/internal/config"
)

func TestEmbeddedIPv4(t *testing.T) {
	cases := []struct {
		name     string
		ip       string
		prefixes []string
		want     string // "" = nil
	}{
		{"ipv4-mapped", "::ffff:1.2.3.4", nil, "1.2.3.4"},
		{"nat64-well-known-96", "64:ff9b::1.2.3.4", []string{"64:ff9b::/96"}, "1.2.3.4"},
		{"nat64-custom-96", "2001:db8:64::1.2.3.4", []string{"2001:db8:64::/96"}, "1.2.3.4"},
		{"nat64-64", "2001:db8:0:0:0:0:0:0", nil, ""}, // u 字节非零场景
		{"no-match", "2001:db8::1", []string{"64:ff9b::/96"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := embeddedIPv4(net.ParseIP(c.ip), c.prefixes)
			if c.want == "" {
				if got != nil {
					t.Fatalf("embeddedIPv4(%s)=%v, want nil", c.ip, got)
				}
				return
			}
			if got == nil || got.String() != c.want {
				t.Fatalf("embeddedIPv4(%s)=%v, want %s", c.ip, got, c.want)
			}
		})
	}
}

func TestBindingTableLookup(t *testing.T) {
	bt := newBindingTable()
	bt.add("2001:db8::/32", "1.1.1.1", "", "")
	bt.add("2001:db8:100::/48", "2.2.2.2", "", "")

	v, ok := bt.Lookup(net.ParseIP("2001:db8:100::1"))
	if !ok || v.String() != "2.2.2.2" {
		t.Fatalf("LPM should prefer /48, got %v/%v", v, ok)
	}
	v, ok = bt.Lookup(net.ParseIP("2001:db8:200::1"))
	if !ok || v.String() != "1.1.1.1" {
		t.Fatalf("LPM should fall back to /32, got %v/%v", v, ok)
	}
	if _, ok := bt.Lookup(net.ParseIP("2001:db9::1")); ok {
		t.Fatal("unexpected match")
	}
}

func newTestDualstack(t *testing.T, ipv6CSV string) *Dualstack {
	t.Helper()
	v4path := writeTemp(t, "qqwry.dat", buildQQwryMode0()) // 1.2.3.0 -> CityA/isp1
	v6path := writeTemp(t, "ipv6.csv", []byte(ipv6CSV))
	cfg := &config.Config{
		NAT64Prefixes: []string{"64:ff9b::/96"},
		ECSDeriveMask: 32,
		GeoIPv4File:   v4path,
		GeoIPv6File:   v6path,
	}
	return NewDualstack(cfg)
}

func TestDeriveECSPass(t *testing.T) {
	d := newTestDualstack(t, "64:ff9b::/96,CN,CityA,CityA,ISP1\n")
	ecs := d.DeriveECS(context.Background(), net.ParseIP("64:ff9b::1.2.3.4"))
	if ecs == nil {
		t.Fatal("DeriveECS returned nil, want ECS")
	}
	if ecs.Family != 1 || ecs.Address.String() != "1.2.3.4" || ecs.Source != 32 {
		t.Fatalf("ecs=%+v, want 1.2.3.4/32 family1", ecs)
	}
}

func TestDeriveECSFailOnMismatch(t *testing.T) {
	d := newTestDualstack(t, "64:ff9b::/96,CN,CityA,CityA,ISP2\n") // 运营商不一致
	if ecs := d.DeriveECS(context.Background(), net.ParseIP("64:ff9b::1.2.3.4")); ecs != nil {
		t.Fatalf("mismatch should yield nil ECS, got %+v", ecs)
	}
}

func TestDeriveECSFailClosedWithoutVerifier(t *testing.T) {
	cfg := &config.Config{NAT64Prefixes: []string{"64:ff9b::/96"}} // 未配置 geo 库
	d := NewDualstack(cfg)
	if ecs := d.DeriveECS(context.Background(), net.ParseIP("64:ff9b::1.2.3.4")); ecs != nil {
		t.Fatalf("without verifier should fail-closed, got %+v", ecs)
	}
}

func TestDeriveECSIgnoresIPv4Client(t *testing.T) {
	d := newTestDualstack(t, "64:ff9b::/96,CN,CityA,CityA,ISP1\n")
	if ecs := d.DeriveECS(context.Background(), net.ParseIP("1.2.3.4")); ecs != nil {
		t.Fatalf("IPv4 client should not trigger derivation, got %+v", ecs)
	}
}
