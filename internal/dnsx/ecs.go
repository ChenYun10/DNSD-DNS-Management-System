package dnsx

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// ECS (EDNS Client Subnet, RFC 7871) support:
//   - ecsFromMsg: extract the client subnet from an incoming query
//   - attachECS:  inject an ECS option into an outgoing query (ECS 传递)
//   - normalize:  clamp/validate subnets
//
// The platform uses ECS both for geo-aware upstream resolution and as the
// scope of cache entries, enabling per-subnet cached answers and dynamic
// cache pre-warming for active subnets.

type ECSInfo struct {
	Family    uint16 // 1 = IPv4, 2 = IPv6
	Source    uint8  // prefix length of the client subnet
	Scope     uint8  // prefix length the upstream applied
	Address   net.IP // masked client address
	HasOption bool
}

// ecsFromMsg extracts the EDNS Client Subnet option from a query.
func ecsFromMsg(m *dns.Msg) *ECSInfo {
	opt := m.IsEdns0()
	if opt == nil {
		return &ECSInfo{}
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			info := &ECSInfo{
				Family:    e.Family,
				Source:    e.SourceNetmask,
				Scope:     e.SourceScope,
				Address:   e.Address,
				HasOption: true,
			}
			info.normalize()
			return info
		}
	}
	return &ECSInfo{}
}

func (e *ECSInfo) normalize() {
	if e.Source == 0 {
		e.Source = 24
	}
	if e.Source > 32 && e.Family == 1 {
		e.Source = 32
	}
	if e.Source > 128 && e.Family == 2 {
		e.Source = 128
	}
	if e.Address == nil {
		return
	}
	if e.Family == 1 && len(e.Address) == net.IPv4len && e.Source < 32 {
		e.Address = e.Address.Mask(net.CIDRMask(int(e.Source), 32))
	}
	if e.Family == 2 && len(e.Address) == net.IPv6len && e.Source < 128 {
		e.Address = e.Address.Mask(net.CIDRMask(int(e.Source), 128))
	}
}

// String renders the ECS as "addr/prefix" or "" when absent.
func (e *ECSInfo) String() string {
	if e == nil || !e.HasOption || e.Address == nil {
		return ""
	}
	return fmt.Sprintf("%s/%d", e.Address.String(), e.Source)
}

// ScopeKey renders a short cache-scope token: "/24" style or full for /0.
func (e *ECSInfo) ScopeKey() string {
	if e == nil || !e.HasOption {
		return "g"
	}
	if e.Source == 0 || e.Address == nil {
		return "g"
	}
	return fmt.Sprintf("%s/%d", e.Address.String(), e.Source)
}

// attachECS clones the query and attaches an ECS option (used for
// ECS 传递 to upstreams and for ECS simulation).
func attachECS(m *dns.Msg, ecs *ECSInfo) *dns.Msg {
	out := m.Copy()
	if ecs == nil || !ecs.HasOption {
		return out
	}
	opt := out.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		out.Extra = append(out.Extra, opt)
	}
	opt.SetUDPSize(4096)
	// strip any existing subnet option to avoid duplicates
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); !ok {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        ecs.Family,
		SourceNetmask: ecs.Source,
		SourceScope:   0,
		Address:       ecs.Address,
	})
	return out
}

// stripECS removes the ECS option from an upstream response before it is
// returned to the client (we echo our own scope in the response instead).
func stripECS(m *dns.Msg) *dns.Msg {
	opt := m.IsEdns0()
	if opt == nil {
		return m
	}
	filtered := opt.Option[:0]
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); !ok {
			filtered = append(filtered, o)
		}
	}
	opt.Option = filtered
	return m
}

// echoECS attaches a minimal ECS scope response option (RFC 7871 §7.2.2).
func echoECS(m *dns.Msg, ecs *ECSInfo) {
	if ecs == nil || !ecs.HasOption {
		return
	}
	opt := m.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		m.Extra = append(m.Extra, opt)
	}
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); ok {
			return // already present
		}
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        ecs.Family,
		SourceNetmask: ecs.Source,
		SourceScope:   ecs.Scope,
		Address:       ecs.Address,
	})
}

// ParseECS is the exported wrapper used by the API layer.
func ParseECS(s string) (*ECSInfo, error) { return parseECSFromString(s) }

// parseECSFromString parses "1.2.3.4/24" or "2001:db8::/48" or a bare IP.
func parseECSFromString(s string) (*ECSInfo, error) {
	if s == "" {
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err == nil {
		ones, _ := ipnet.Mask.Size()
		ip := ipnet.IP
		family := uint16(1)
		if ip.To4() == nil {
			family = 2
		} else {
			ip = ip.To4()
		}
		return &ECSInfo{Family: family, Source: uint8(ones), Address: ip, HasOption: true}, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid ECS %q", s)
	}
	if ip.To4() != nil {
		return &ECSInfo{Family: 1, Source: 32, Address: ip.To4(), HasOption: true}, nil
	}
	return &ECSInfo{Family: 2, Source: 128, Address: ip, HasOption: true}, nil
}

// ecsToCacheString gives a stable cache token, e.g. "203.0.113.0/24".
func ecsToCacheString(e *ECSInfo) string {
	if e == nil || !e.HasOption || e.Address == nil || e.Source == 0 {
		return ""
	}
	return e.String()
}

// packUint16 / unpackUint16 helpers kept for DoQ framing elsewhere
func packUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
