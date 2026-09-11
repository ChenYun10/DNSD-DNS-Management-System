// Package threatintel 提供恶意域名主动发现能力：
//
//  1. 对接本地威胁情报中心（HTTP API，POST JSON）查询域名信誉；
//  2. 本地黑名单文件（精确匹配 + *.domain 通配符）；
//  3. 内存缓存（避免对同一域名重复查询情报中心）；
//  4. 命中后由 Broadcaster 通过 UDP 向局域网广播告警。
//
// 情报中心接口约定（对接 MISP / OpenCTI / 自建情报库时按此实现一个薄适配层）：
//
//	POST {THREAT_INTEL_URL}
//	Content-Type: application/json
//	Authorization: Bearer {THREAT_INTEL_TOKEN}   （可选）
//	请求体: {"domain": "example.com"}
//	响应体: {"malicious": true, "category": "malware", "severity": "high"}
package threatintel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"dns-platform/internal/config"
)

// ThreatInfo 是一条威胁命中信息。
type ThreatInfo struct {
	Domain     string    `json:"domain"`
	Source     string    `json:"source"`   // api | blacklist
	Category   string    `json:"category"` // malware | phishing | c2 | botnet | ...
	Severity   string    `json:"severity"` // low | medium | high | critical
	DetectedAt time.Time `json:"detected_at"`
}

// Client 对接本地情报中心 + 本地黑名单 + 内存缓存。并发安全。
type Client struct {
	apiURL    string
	token     string
	http      *http.Client
	blacklist *blacklist
	cacheTTL  time.Duration

	blockMode string   // off | 127.0.0.1 | random
	blockPool []net.IP // random 模式的 sinkhole IP 池
	blocked   sync.Map // 已回填的恶意域名 -> 拦截时间（进程内有效）

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	hit  *ThreatInfo // nil = 干净域名
	seen time.Time
}

// NewClient 构造情报客户端。THREAT_INTEL_URL 为空时仅使用本地黑名单。
func NewClient(cfg *config.Config) *Client {
	c := &Client{
		apiURL:   cfg.ThreatIntelURL,
		token:    cfg.ThreatIntelToken,
		http:     &http.Client{Timeout: cfg.ThreatIntelTimeout},
		cacheTTL: cfg.ThreatIntelCacheTTL,
		cache:    make(map[string]cacheEntry),
	}
	if cfg.ThreatIntelBlacklistFile != "" {
		c.blacklist = loadBlacklist(cfg.ThreatIntelBlacklistFile)
	}
	c.blockMode = strings.ToLower(cfg.ThreatBlockMode)
	for _, s := range strings.Split(cfg.ThreatBlockPool, ",") {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			c.blockPool = append(c.blockPool, ip)
		}
	}
	return c
}

// Check 查询域名是否命中恶意情报，返回 nil 表示未命中。
func (c *Client) Check(ctx context.Context, domain string) *ThreatInfo {
	domain = normalize(domain)
	if domain == "" {
		return nil
	}

	// 1. 内存缓存命中
	c.mu.RLock()
	if e, ok := c.cache[domain]; ok && time.Since(e.seen) < c.cacheTTL {
		c.mu.RUnlock()
		return e.hit
	}
	c.mu.RUnlock()

	var hit *ThreatInfo

	// 2. 本地黑名单（优先，零网络开销）
	if c.blacklist != nil && c.blacklist.matches(domain) {
		hit = &ThreatInfo{Domain: domain, Source: "blacklist", Category: "blocked", Severity: "high", DetectedAt: time.Now()}
	}

	// 3. 情报中心 API
	if hit == nil && c.apiURL != "" {
		hit = c.lookupAPI(ctx, domain)
	}

	// 4. 写缓存
	c.mu.Lock()
	c.cache[domain] = cacheEntry{hit: hit, seen: time.Now()}
	c.mu.Unlock()

	// 5. 命中则回填内存拦截表，后续查询同步短路
	if hit != nil {
		c.rememberBlocked(domain)
	}
	return hit
}

// Block 同步判断域名是否应被拦截。返回命中信息 + sinkhole IP；nil 表示放行。
// 仅查询本地数据（黑名单 + 已回填情报），零网络 I/O，可安全放在解析主路径。
func (c *Client) Block(domain string) (*ThreatInfo, net.IP) {
	if c.blockMode == "" || c.blockMode == "off" {
		return nil, nil
	}
	domain = normalize(domain)
	if domain == "" {
		return nil, nil
	}
	if c.blacklist != nil && c.blacklist.matches(domain) {
		return &ThreatInfo{Domain: domain, Source: "blacklist", Category: "blocked", Severity: "high", DetectedAt: time.Now()}, c.sinkholeIP()
	}
	if _, ok := c.blocked.Load(domain); ok {
		return &ThreatInfo{Domain: domain, Source: "api", Category: "blocked", Severity: "high", DetectedAt: time.Now()}, c.sinkholeIP()
	}
	return nil, nil
}

// sinkholeIP 返回拦截响应的 IP：random 模式从池中随机，否则固定 127.0.0.1。
func (c *Client) sinkholeIP() net.IP {
	if c.blockMode == "random" && len(c.blockPool) > 0 {
		return c.blockPool[rand.Intn(len(c.blockPool))]
	}
	return net.IPv4(127, 0, 0, 1)
}

// rememberBlocked 将命中域名写入内存拦截表（进程内有效，重启后由情报中心重新回填）。
func (c *Client) rememberBlocked(domain string) {
	if c.blockMode == "" || c.blockMode == "off" {
		return
	}
	c.blocked.Store(domain, time.Now())
}

// lookupAPI 查询本地威胁情报中心。任何错误都返回 nil（fail-open，不误伤）。
func (c *Client) lookupAPI(ctx context.Context, domain string) *ThreatInfo {
	body, _ := json.Marshal(map[string]string{"domain": domain})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("[threat] intel api unreachable for %s: %v", domain, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[threat] intel api status %d for %s", resp.StatusCode, domain)
		return nil
	}

	var out struct {
		Malicious bool   `json:"malicious"`
		Category  string `json:"category"`
		Severity  string `json:"severity"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Printf("[threat] intel api decode error for %s: %v", domain, err)
		return nil
	}
	if !out.Malicious {
		return nil
	}
	if out.Severity == "" {
		out.Severity = "medium"
	}
	if out.Category == "" {
		out.Category = "malicious"
	}
	return &ThreatInfo{Domain: domain, Source: "api", Category: out.Category, Severity: out.Severity, DetectedAt: time.Now()}
}

// normalize 规范化域名为小写、无尾点。
func normalize(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// blacklist 本地黑名单（精确匹配 + 通配符后缀）。
type blacklist struct {
	exact    map[string]bool
	wildcard []string // 形如 ".example.com" 的后缀
}

func loadBlacklist(path string) *blacklist {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[threat] load blacklist file %s failed: %v", path, err)
		return nil
	}
	defer f.Close()

	b := &blacklist{exact: make(map[string]bool)}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := strings.ToLower(strings.TrimSuffix(line, "."))
		if strings.HasPrefix(d, "*.") {
			b.wildcard = append(b.wildcard, "."+strings.TrimPrefix(d, "*."))
		} else {
			b.exact[d] = true
		}
	}
	log.Printf("[threat] blacklist loaded: %d exact, %d wildcard from %s", len(b.exact), len(b.wildcard), path)
	return b
}

func (b *blacklist) matches(domain string) bool {
	if b == nil {
		return false
	}
	if b.exact[domain] {
		return true
	}
	for _, suf := range b.wildcard {
		if strings.HasSuffix(domain, suf) {
			return true
		}
	}
	return false
}
