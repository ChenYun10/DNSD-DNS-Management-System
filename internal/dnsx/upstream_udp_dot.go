package dnsx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
)

// ---------------------------------------------------------------------------
// Traditional UDP/TCP upstream (dns.Client)
// ---------------------------------------------------------------------------

type udpClient struct {
	cfg  *config.Config
	up   *model.Upstream
	addr string
	udp  *dns.Client
	tcp  *dns.Client
}

func newUDPClient(cfg *config.Config, u *model.Upstream, addr string) *udpClient {
	return &udpClient{
		cfg:  cfg,
		up:   u,
		addr: addr,
		udp: &dns.Client{
			Net:     "udp",
			Timeout: cfg.UpstreamTimeout,
			UDPSize: 4096,
		},
		tcp: &dns.Client{
			Net:     "tcp",
			Timeout: cfg.UpstreamTimeout,
		},
	}
}

func (c *udpClient) String() string { return fmt.Sprintf("udp/tcp://%s", c.addr) }

func (c *udpClient) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	if c.up.Protocol == model.ProtoTCP {
		return c.exchangeTCP(ctx, m)
	}
	r, _, err := c.udp.ExchangeContext(ctx, m, c.addr)
	return r, err
}

func (c *udpClient) exchangeTCP(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, _, err := c.tcp.ExchangeContext(ctx, m, c.addr)
	return r, err
}

func (c *udpClient) HealthProbe(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.cfg.HealthDomain), dns.TypeA)
	m.SetEdns0(1232, false)
	r, _, err := c.udp.ExchangeContext(ctx, m, c.addr)
	if err != nil {
		return err
	}
	if r.Rcode == dns.RcodeServerFailure {
		return fmt.Errorf("SERVFAIL from %s", c.addr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// DNS over TLS (DoT, RFC 7858)
// ---------------------------------------------------------------------------

type dotClient struct {
	cfg  *config.Config
	up   *model.Upstream
	addr string
	cli  *dns.Client
}

func newDoTClient(cfg *config.Config, u *model.Upstream, addr string) *dotClient {
	return &dotClient{
		cfg:  cfg,
		up:   u,
		addr: addr,
		cli: &dns.Client{
			Net:       "tcp-tls",
			Timeout:   cfg.UpstreamTimeout,
			TLSConfig: tlsConfigForUpstream(cfg, u),
		},
	}
}

func (c *dotClient) String() string { return fmt.Sprintf("dot://%s", c.addr) }

func (c *dotClient) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	r, _, err := c.cli.ExchangeContext(ctx, m, c.addr)
	return r, err
}

func (c *dotClient) HealthProbe(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.cfg.HealthDomain), dns.TypeA)
	r, _, err := c.cli.ExchangeContext(ctx, m, c.addr)
	if err != nil {
		return err
	}
	if r.Rcode == dns.RcodeServerFailure {
		return fmt.Errorf("SERVFAIL from %s", c.addr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH, RFC 8484)
// ---------------------------------------------------------------------------

type dohClient struct {
	cfg *config.Config
	up  *model.Upstream
	url string
	hc  *httpClient
}

func newDoHClient(cfg *config.Config, u *model.Upstream, addr string) *dohClient {
	path := u.DoHPath
	if path == "" {
		path = "/dns-query"
	}
	scheme := "https"
	if u.TLSInsecure && cfg.Env == "dev" {
		// still https, but skip-verify; http:// is not allowed
	}
	return &dohClient{
		cfg: cfg,
		up:  u,
		url: fmt.Sprintf("%s://%s%s", scheme, addr, path),
		hc:  newHTTPClient(cfg, u),
	}
}

func (c *dohClient) String() string { return fmt.Sprintf("doh://%s", c.url) }

func (c *dohClient) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	return c.hc.exchange(ctx, m, c.url)
}

func (c *dohClient) HealthProbe(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.cfg.HealthDomain), dns.TypeA)
	_, err := c.hc.exchange(ctx, m, c.url)
	return err
}

// httpClient is a shared hardened HTTP client used by DoH upstream and the
// DoH downstream handler.
func newHTTPClient(cfg *config.Config, u *model.Upstream) *httpClient {
	tlsCfg := tlsConfigForUpstream(cfg, u)
	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &httpClient{cli: &http.Client{Transport: tr}}
}

// httpClient performs RFC 8484 exchanges (application/dns-message POST).
type httpClient struct {
	cli *http.Client
}

func (h *httpClient) exchange(ctx context.Context, m *dns.Msg, url string) (*dns.Msg, error) {
	raw, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := h.cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("doh upstream status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}
