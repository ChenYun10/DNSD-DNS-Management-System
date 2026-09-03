package dnsx

// IPv6 → IPv4 双栈映射（内网 IPv6 接入 → 客户端真实 IPv4 → 透传 ECS）。
//
// 映射按优先级依次尝试三个来源：
//  1. 内嵌：IPv4-mapped（::ffff:a.b.c.d）与 RFC6052 NAT64 前缀内嵌
//  2. 绑定表：IPv6 子网 → IPv4 的最长前缀匹配（文件 CSV + MySQL 合并）
//  3. 外部 API：HTTP 接口按 IPv6 查真实 IPv4
//
// 推导出 IPv4 后，必须用 IP 归属地/运营商库校验 IPv6 与 IPv4 指向同一
// 物理归属地/运营商；校验失败或未配置校验库时一律不携带 ECS（fail-closed）。

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
)

// Dualstack 是 IPv6→IPv4 推导与一致性校验的编排器。
type Dualstack struct {
	cfg *config.Config

	mu    sync.RWMutex
	table *BindingTable

	verifier *Verifier
	apiCli   *http.Client
}

// NewDualstack 构造 Dualstack：加载 IP 归属地/运营商库并做一次初始绑定表加载。
func NewDualstack(cfg *config.Config) *Dualstack {
	d := &Dualstack{
		cfg:    cfg,
		apiCli: &http.Client{Timeout: cfg.MapAPITimeout},
	}
	var v4, v6 IPDB
	if cfg.GeoIPv4File != "" {
		if db, err := NewQQwry(cfg.GeoIPv4File); err == nil {
			v4 = db
		} else {
			log.Printf("[dualstack] load GeoIPv4File %s failed: %v", cfg.GeoIPv4File, err)
		}
	}
	if cfg.GeoIPv6File != "" {
		if db, err := NewIPv6CSV(cfg.GeoIPv6File); err == nil {
			v6 = db
		} else {
			log.Printf("[dualstack] load GeoIPv6File %s failed: %v", cfg.GeoIPv6File, err)
		}
	}
	if v4 != nil && v6 != nil {
		d.verifier = NewVerifier(v4, v6, cfg.GeoStrictCity)
	} else {
		log.Printf("[dualstack] verifier unavailable (both GEO_IPV4_FILE and GEO_IPV6_FILE required)")
	}
	d.Reload(nil)
	return d
}

// Reload 重建绑定表：先加载文件，再合并 MySQL 绑定记录。
// bindings 为 nil 时仅加载文件（用于初始构造）。
func (d *Dualstack) Reload(bindings []*model.DualstackBinding) {
	t := newBindingTable()
	if d.cfg.MapFile != "" {
		t.loadFile(d.cfg.MapFile)
	}
	for _, b := range bindings {
		if b == nil || !b.Enabled {
			continue
		}
		t.add(b.IPv6Subnet, b.IPv4, b.ISP, b.Region)
	}
	d.mu.Lock()
	d.table = t
	d.mu.Unlock()
}

// DeriveECS 从内网 IPv6 客户端地址推导真实 IPv4，并（校验一致后）封装为 ECS。
// 返回 nil 表示不携带 ECS（映射失败 / 校验失败 / 未配置校验库）。
func (d *Dualstack) DeriveECS(ctx context.Context, clientIP net.IP) *ECSInfo {
	if d == nil || clientIP == nil || clientIP.To4() != nil {
		return nil // 仅处理 IPv6 客户端
	}
	if d.verifier == nil {
		return nil // 未配置校验库，fail-closed
	}
	v4, source := d.mapToIPv4(ctx, clientIP)
	if v4 == nil {
		return nil
	}
	if ok, reason := d.verifier.Verify(clientIP, v4); !ok {
		log.Printf("[dualstack] verify failed for %s -> %s: %s", clientIP, v4, reason)
		return nil
	}
	mask := d.cfg.ECSDeriveMask
	if mask <= 0 {
		mask = 32
	}
	v4 = v4.To4()
	if mask < 32 {
		v4 = v4.Mask(net.CIDRMask(mask, 32))
	}
	log.Printf("[dualstack] derive %s -> %s (source=%s, ecs=/%d)", clientIP, v4, source, mask)
	return &ECSInfo{Family: 1, Source: uint8(mask), Address: v4, HasOption: true}
}

// mapToIPv4 按优先级尝试三级映射。
func (d *Dualstack) mapToIPv4(ctx context.Context, ipv6 net.IP) (net.IP, string) {
	// 1. 内嵌（IPv4-mapped / NAT64）
	if v4 := embeddedIPv4(ipv6, d.cfg.NAT64Prefixes); v4 != nil {
		return v4, "embedded"
	}
	// 2. 绑定表（最长前缀匹配）
	d.mu.RLock()
	t := d.table
	d.mu.RUnlock()
	if t != nil {
		if v4, ok := t.Lookup(ipv6); ok {
			return v4, "table"
		}
	}
	// 3. 外部 API
	if d.cfg.MapAPIURL != "" {
		if v4, ok := d.mapViaAPI(ctx, ipv6); ok {
			return v4, "api"
		}
	}
	return nil, ""
}

// mapViaAPI 调用外部 HTTP 接口查询真实 IPv4。支持 JSON {"ipv4":"..."} 或纯文本。
func (d *Dualstack) mapViaAPI(ctx context.Context, ipv6 net.IP) (net.IP, bool) {
	url := strings.ReplaceAll(d.cfg.MapAPIURL, "{ip}", ipv6.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false
	}
	resp, err := d.apiCli.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, false
	}
	var obj struct {
		IPv4 string `json:"ipv4"`
	}
	if json.Unmarshal(body, &obj) == nil && obj.IPv4 != "" {
		if ip := net.ParseIP(strings.TrimSpace(obj.IPv4)); ip != nil {
			return ip.To4(), ip.To4() != nil
		}
	}
	if ip := net.ParseIP(strings.TrimSpace(string(body))); ip != nil {
		return ip.To4(), ip.To4() != nil
	}
	return nil, false
}

// embeddedIPv4 从 IPv4-mapped 或 NAT64 前缀中提取内嵌 IPv4。
func embeddedIPv4(ip net.IP, nat64Prefixes []string) net.IP {
	if ip == nil {
		return nil
	}
	// IPv4-mapped IPv6（::ffff:a.b.c.d）——net.IP.To4 直接返回 IPv4。
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil
	}
	for _, p := range nat64Prefixes {
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(p))
		if err != nil || ipnet == nil || !ipnet.Contains(v6) {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		if v4 := extractRFC6052(v6, ones); v4 != nil {
			return v4
		}
	}
	return nil
}

// extractRFC6052 按 RFC 6052 从 IPv6 地址提取内嵌 IPv4（常见前缀长度）。
func extractRFC6052(v6 net.IP, pl int) net.IP {
	if len(v6) != 16 {
		return nil
	}
	b := v6
	var v4 [4]byte
	switch pl {
	case 32:
		if b[8] != 0 {
			return nil
		}
		copy(v4[:], b[4:8])
	case 40:
		if b[8] != 0 {
			return nil
		}
		v4[0], v4[1], v4[2], v4[3] = b[5], b[6], b[7], b[9]
	case 48:
		if b[8] != 0 {
			return nil
		}
		v4[0], v4[1], v4[2], v4[3] = b[6], b[7], b[9], b[10]
	case 56:
		if b[8] != 0 {
			return nil
		}
		v4[0], v4[1], v4[2], v4[3] = b[7], b[9], b[10], b[11]
	case 64:
		if b[8] != 0 {
			return nil
		}
		v4[0], v4[1], v4[2], v4[3] = b[9], b[10], b[11], b[12]
	case 96:
		v4[0], v4[1], v4[2], v4[3] = b[12], b[13], b[14], b[15]
	default:
		return nil
	}
	return net.IPv4(v4[0], v4[1], v4[2], v4[3])
}

// ---------------------------------------------------------------------------
// 绑定表（IPv6 子网 → IPv4，最长前缀匹配）
// ---------------------------------------------------------------------------

// BindingEntry is one IPv6-subnet → IPv4 mapping.
type BindingEntry struct {
	Net    *net.IPNet
	IPv4   net.IP
	ISP    string
	Region string
}

// BindingTable holds bindings for longest-prefix-match lookup.
type BindingTable struct {
	entries []BindingEntry
}

func newBindingTable() *BindingTable { return &BindingTable{} }

func (t *BindingTable) add(cidr, ipv4, isp, region string) {
	cidr = strings.TrimSpace(cidr)
	ipv4 = strings.TrimSpace(ipv4)
	if cidr == "" || ipv4 == "" {
		return
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil || n == nil {
		return
	}
	ip := net.ParseIP(ipv4)
	if ip == nil || ip.To4() == nil {
		return
	}
	t.entries = append(t.entries, BindingEntry{
		Net:    n,
		IPv4:   ip.To4(),
		ISP:    strings.TrimSpace(isp),
		Region: strings.TrimSpace(region),
	})
}

// Lookup returns the IPv4 for the longest matching IPv6 subnet.
func (t *BindingTable) Lookup(ip net.IP) (net.IP, bool) {
	if t == nil || ip == nil {
		return nil, false
	}
	best := -1
	bestLen := -1
	for i, e := range t.entries {
		if e.Net.Contains(ip) {
			ones, _ := e.Net.Mask.Size()
			if ones > bestLen {
				best, bestLen = i, ones
			}
		}
	}
	if best < 0 {
		return nil, false
	}
	return t.entries[best].IPv4, true
}

// loadFile 从 CSV 文件加载绑定：每行 "ipv6_subnet,ipv4[,isp[,region]]"。
func (t *BindingTable) loadFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[dualstack] read map file %s failed: %v", path, err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		isp, region := "", ""
		if len(parts) >= 3 {
			isp = parts[2]
		}
		if len(parts) >= 4 {
			region = parts[3]
		}
		t.add(parts[0], parts[1], isp, region)
	}
}
