package dnsx

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
)

// connReadTimeout 是 DoT/DoQ 等长连接上单次读取的超时上限，用于防御慢速连接
// 资源耗尽（slowloris）。
const connReadTimeout = 30 * time.Second

// Server binds all downstream listeners:
//
//	:53   UDP + TCP  — traditional DNS (enterprise resolvers, ECS carriers)
//	:853  DoT        — per-tenant custom prefixes via SNI (DoT 前缀定制)
//	:8443 DoH        — https://{prefix}.base/dns-query (DoH 部署)
//	:784  DoQ        — RFC 9250
//
// TLS uses a wildcard cert for *.BaseDomain. The SNI prefix is resolved to a
// tenant and carried into the pipeline via RequestMeta. Unknown/disabled
// prefixes are rejected at the TLS handshake layer (no DNS probing).
type Server struct {
	cfg  *config.Config
	core *Core

	udp    *dns.Server
	tcp    *dns.Server
	intUDP *dns.Server // 内网专用 UDP 监听（IPv6 双栈 ECS 推导）
	intTCP *dns.Server // 内网专用 TCP 监听
	doh    *http.Server
	doq    *quic.Listener

	tlsConf   *tls.Config
	certStore *CertStore

	lns  []net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	errs []error
}

func NewServer(cfg *config.Config, core *Core) (*Server, error) {
	s := &Server{cfg: cfg, core: core, certStore: NewCertStore(cfg.CertDir)}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}
	s.tlsConf = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// ALPN covers all protocols; per-listener clones narrow it. The
		// config returned by GetConfigForClient must keep NextProtos or
		// DoH/DoQ handshakes fail ALPN negotiation.
		NextProtos: []string{"dot", "doq", "h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		// Per-connection tenant resolution by SNI. Custom main domains
		// (customer-owned) get their own certificate; unknown prefixes/names
		// fail the handshake → the inventory is never enumerable.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			host := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
			ctx := context.Background()
			// 1) customer custom main domain (tenant_domains) + its cert
			if t, err := core.repos.TenantByDomain(ctx, host); err == nil && t != nil && t.DoTEnabled {
				if cert := s.certStore.Get(host); cert != nil {
					cc := s.tlsConf.Clone()
					cc.Certificates = []tls.Certificate{*cert}
					return cc, nil
				}
				return s.tlsConf.Clone(), nil
			}
			// 2) exact platform base domain (wildcard cert)
			base := strings.ToLower(strings.TrimSuffix(cfg.BaseDomain, "."))
			if host == base {
				return s.tlsConf.Clone(), nil
			}
			// 3) tenant prefix routing: 仅已注册且启用的前缀放行; 未知前缀在此
			//    握手层拒绝, 修复此前“任意 *.base_domain 子域都放行”导致的前缀
			//    隔离失效。
			prefix := prefixFromSNI(host, cfg.BaseDomain)
			if prefix == "" {
				return nil, errors.New("unrecognized server name")
			}
			t, err := core.repos.TenantByPrefix(ctx, prefix)
			if err != nil || t == nil || !t.DoTEnabled {
				return nil, errors.New("unknown or disabled DoT prefix")
			}
			return s.tlsConf.Clone(), nil
		},
	}

	handler := dns.HandlerFunc(core.ServeDNS)
	s.udp = &dns.Server{Addr: cfg.DNSListenUDP, Net: "udp", Handler: handler, UDPSize: 4096}
	s.tcp = &dns.Server{Addr: cfg.DNSListenTCP, Net: "tcp", Handler: handler}

	// 内网专用监听：面向内网 IPv6 接入客户端，标记 Internal=true，触发
	// 双栈 IPv6→IPv4 ECS 推导。地址为空则禁用。
	if cfg.IntListenUDP != "" {
		s.intUDP = &dns.Server{Addr: cfg.IntListenUDP, Net: "udp", Handler: s.internalHandler(), UDPSize: 4096}
	}
	if cfg.IntListenTCP != "" {
		s.intTCP = &dns.Server{Addr: cfg.IntListenTCP, Net: "tcp", Handler: s.internalHandler()}
	}

	dohTLS := s.tlsConf.Clone()
	dohTLS.NextProtos = []string{"h2", "http/1.1"}
	s.doh = &http.Server{
		Addr:              cfg.DoHListen,
		Handler:           s.dohHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         dohTLS,
	}
	return s, nil
}

// Start launches all listeners. UDP/TCP use miekg/dns; DoT/DoQ use custom
// TLS/QUIC listeners so the SNI prefix can drive tenant routing.
func (s *Server) Start() error {
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.serve("udp", func() error { return s.udp.ListenAndServe() }) }()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.serve("tcp", func() error { return s.tcp.ListenAndServe() }) }()
	if s.intUDP != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serve("int-udp", func() error { return s.intUDP.ListenAndServe() }) }()
	}
	if s.intTCP != nil {
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.serve("int-tcp", func() error { return s.intTCP.ListenAndServe() }) }()
	}
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.serve("doh", func() error { return s.doh.ListenAndServeTLS("", "") }) }()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.serve("dot", func() error { return s.startDoT() }) }()
	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.serve("doq", func() error { return s.startDoQ() }) }()

	// brief window to catch bind errors (e.g. port in use)
	time.Sleep(400 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) > 0 {
		return s.errs[0]
	}
	return nil
}

func (s *Server) serve(name string, fn func() error) {
	if err := fn(); err != nil {
		log.Printf("[server] %s stopped: %v", name, err)
		s.mu.Lock()
		s.errs = append(s.errs, err)
		s.mu.Unlock()
	}
}

// internalHandler 包装内网监听请求：标记 Internal=true，触发双栈 ECS 推导。
func (s *Server) internalHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		cw := &ctxWriter{ResponseWriter: w, internal: true, clientIP: clientIP(w.RemoteAddr())}
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			cw.via = "int-tcp"
		} else {
			cw.via = "int-udp"
		}
		s.core.ServeDNS(cw, r)
	})
}

// --- DoT listener (RFC 7858) with SNI-based tenant routing ---

func (s *Server) startDoT() error {
	ln, err := net.Listen("tcp", s.cfg.DoTListen)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.lns = append(s.lns, ln)
	s.mu.Unlock()
	dotTLS := s.tlsConf.Clone()
	dotTLS.NextProtos = []string{"dot"}
	tlsLn := tls.NewListener(ln, dotTLS)
	log.Printf("[server] DoT listening on %s", s.cfg.DoTListen)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			return err
		}
		go s.serveDoTConn(conn)
	}
}

func (s *Server) serveDoTConn(conn net.Conn) {
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	// 握手与后续读取均设置截止时间，防止慢速连接（slowloris）无限占用 goroutine/连接。
	tc.SetDeadline(time.Now().Add(connReadTimeout))
	if err := tc.Handshake(); err != nil {
		return
	}
	tc.SetDeadline(time.Time{}) // 握手完成后清除整体截止时间，改由读取循环逐次设置
	sni := tc.ConnectionState().ServerName
	meta := &RequestMeta{Via: "dot", SNI: sni}
	meta.Prefix = prefixFromSNI(sni, s.cfg.BaseDomain)
	if t, _ := s.resolveTenant(context.Background(), sni); t != nil {
		meta.Tenant = t
	}
	meta.ClientIP = clientIP(conn.RemoteAddr())

	// RFC 7858: DNS messages are carried directly over the TLS stream.
	// For compatibility with BIND's dig (which sends the RFC 1035 TCP-style
	// 2-byte length prefix), both framings are accepted; the detected framing
	// is used for the response.
	r := bufio.NewReader(tc)
	for {
		tc.SetReadDeadline(time.Now().Add(connReadTimeout))
		msg, framing, err := readDNSMessageCompat(r)
		if err != nil {
			return
		}
		resp, _ := s.core.Process(context.Background(), msg, meta)
		if resp == nil {
			continue
		}
		raw, err := resp.Pack()
		if err != nil {
			continue
		}
		if framing == "prefixed" {
			out := make([]byte, 2+len(raw))
			binary.BigEndian.PutUint16(out, uint16(len(raw)))
			copy(out[2:], raw)
			raw = out
		}
		tc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := tc.Write(raw); err != nil {
			return
		}
	}
}

// readDNSMessageCompat reads one DNS message, auto-detecting the framing:
//   - "raw"      RFC 7858: message bytes directly on the stream
//   - "prefixed" RFC 1035 TCP style: 2-byte big-endian length + message
//
// A length prefix is assumed only when the first two bytes form a plausible
// length AND the prefixed payload unpacks cleanly; otherwise the bytes are
// re-interpreted as the start of a raw message.
func readDNSMessageCompat(r *bufio.Reader) (*dns.Msg, string, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, "", err
	}
	l := int(binary.BigEndian.Uint16(head[:]))
	if l >= 12 && l <= 4096 {
		body := make([]byte, l)
		if _, err := io.ReadFull(r, body); err == nil {
			m := new(dns.Msg)
			if err := m.Unpack(body); err == nil && len(m.Question) >= 1 {
				return m, "prefixed", nil
			}
			// Not a valid prefixed message: treat head+body as a raw message.
			all := append(append([]byte{}, head[:]...), body...)
			m2 := new(dns.Msg)
			if err := m2.Unpack(all); err == nil && len(m2.Question) >= 1 {
				return m2, "raw", nil
			}
		} else {
			// Partial body: likely a raw message whose ID collided with a
			// plausible length. Try the raw interpretation on what we have.
			all := append(append([]byte{}, head[:]...), body...)
			m3 := new(dns.Msg)
			if err := m3.Unpack(all); err == nil && len(m3.Question) >= 1 {
				return m3, "raw", nil
			}
		}
		return nil, "", errors.New("unparseable DNS message")
	}
	// Raw (RFC 7858): head is the start of the message.
	raw := io.MultiReader(bytes.NewReader(head[:]), r)
	msg, err := readRawDNSMessage(bufio.NewReader(raw))
	if err != nil {
		return nil, "", err
	}
	return msg, "raw", nil
}

// readRawDNSMessage reads a single unframed DNS message (RFC 7858) from r by
// walking the header counts and section lengths. Compression pointers in the
// question section are handled (rare but legal).
func readRawDNSMessage(r *bufio.Reader) (*dns.Msg, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 512)
	buf = append(buf, hdr[:]...)
	qd := binary.BigEndian.Uint16(hdr[4:6])
	an := binary.BigEndian.Uint16(hdr[6:8])
	ns := binary.BigEndian.Uint16(hdr[8:10])
	ar := binary.BigEndian.Uint16(hdr[10:12])
	readN := func(n int) error {
		chunk := make([]byte, n)
		if _, err := io.ReadFull(r, chunk); err != nil {
			return err
		}
		buf = append(buf, chunk...)
		return nil
	}
	skipName := func() error {
		for {
			b, err := r.ReadByte()
			if err != nil {
				return err
			}
			buf = append(buf, b)
			if b&0xC0 == 0xC0 { // compression pointer: 2 bytes total
				b2, err := r.ReadByte()
				if err != nil {
					return err
				}
				buf = append(buf, b2)
				return nil
			}
			if b == 0 {
				return nil
			}
			if err := readN(int(b)); err != nil {
				return err
			}
		}
	}
	skipSection := func(count int) error {
		for i := 0; i < count; i++ {
			if err := skipName(); err != nil {
				return err
			}
			var rr [10]byte
			if _, err := io.ReadFull(r, rr[:]); err != nil {
				return err
			}
			buf = append(buf, rr[:]...)
			rdlen := int(binary.BigEndian.Uint16(rr[8:10]))
			if err := readN(rdlen); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < int(qd); i++ {
		if err := skipName(); err != nil {
			return nil, err
		}
		if err := readN(4); err != nil { // qtype + qclass
			return nil, err
		}
	}
	for _, count := range []int{int(an), int(ns), int(ar)} {
		if err := skipSection(count); err != nil {
			return nil, err
		}
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(buf); err != nil {
		return nil, err
	}
	return msg, nil
}

// --- DoH (RFC 8484) ---

func (s *Server) dohHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", s.serveDoH)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"service":"dns-platform-doh","status":"ok","endpoints":["/dns-query"]}`))
	})
	return securityHeaders(mux)
}

func (s *Server) serveDoH(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	meta := &RequestMeta{Via: "doh", SNI: host}
	meta.Prefix = prefixFromSNI(host, s.cfg.BaseDomain)
	if t, _ := s.resolveTenant(r.Context(), host); t != nil {
		meta.Tenant = t
	}
	meta.ClientIP = s.clientIPFromRequest(r)

	var msg *dns.Msg
	switch r.Method {
	case http.MethodGet:
		b64 := r.URL.Query().Get("dns")
		if b64 == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		data, err := decodeBase64URL(b64)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			http.Error(w, "invalid DNS message", http.StatusBadRequest)
			return
		}
	case http.MethodPost:
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/dns-message") {
			http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
			return
		}
		data, err := readBody(w, r, 65535)
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		msg = new(dns.Msg)
		if err := msg.Unpack(data); err != nil {
			http.Error(w, "invalid DNS message", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp, _ := s.core.Process(r.Context(), msg, meta)
	if resp == nil {
		http.Error(w, "no response", http.StatusBadGateway)
		return
	}
	packed, err := resp.Pack()
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(packed)
}

// --- DoQ listener (RFC 9250) ---

func (s *Server) startDoQ() error {
	qcfg := &quic.Config{
		MaxIdleTimeout:        2 * time.Minute,
		MaxIncomingStreams:    4096,
		MaxIncomingUniStreams: -1,
	}
	doqTLS := s.tlsConf.Clone()
	doqTLS.NextProtos = []string{"doq"}
	ln, err := quic.ListenAddr(s.cfg.DoQListen, doqTLS, qcfg)
	if err != nil {
		return err
	}
	s.doq = ln
	log.Printf("[server] DoQ listening on %s", s.cfg.DoQListen)
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return err
		}
		go func(conn *quic.Conn) {
			sni := ""
			if st := conn.ConnectionState(); st.TLS.ServerName != "" {
				sni = st.TLS.ServerName
			}
			doqServeConn(context.Background(), conn, func(ctx context.Context, msg *dns.Msg, clientIP net.IP, meta *RequestMeta) *dns.Msg {
				if sni != "" {
					meta.SNI = sni
					meta.Prefix = prefixFromSNI(sni, s.cfg.BaseDomain)
					if t, _ := s.resolveTenant(ctx, sni); t != nil {
						meta.Tenant = t
					}
				}
				resp, _ := s.core.Process(ctx, msg, meta)
				return resp
			})
		}(conn)
	}
}

// --- lifecycle ---

func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if err := s.udp.ShutdownContext(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.tcp.ShutdownContext(ctx); err != nil {
		errs = append(errs, err)
	}
	if s.intUDP != nil {
		if err := s.intUDP.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.intTCP != nil {
		if err := s.intTCP.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.doh.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if s.doq != nil {
		_ = s.doq.Close()
	}
	s.mu.Lock()
	for _, ln := range s.lns {
		_ = ln.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// --- helpers ---

// resolveTenant maps an SNI/host to a tenant: customer custom main domain
// first (exact or any subdomain), then <prefix>.<base_domain> prefix routing.
func (s *Server) resolveTenant(ctx context.Context, host string) (*model.Tenant, string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, ""
	}
	if t, err := s.core.repos.TenantByDomain(ctx, host); err == nil && t != nil {
		return t, "domain"
	}
	prefix := prefixFromSNI(host, s.cfg.BaseDomain)
	if prefix != "" {
		if t, err := s.core.repos.TenantByPrefix(ctx, prefix); err == nil && t != nil {
			return t, "prefix"
		}
	}
	return nil, ""
}

// RefreshCerts rescans the per-domain certificate directory (called on config
// reload and periodically so newly issued certs are picked up without a
// restart).
func (s *Server) RefreshCerts() {
	s.certStore.Reload()
}

// prefixFromSNI extracts a single-label tenant prefix from "prefix.base".
func prefixFromSNI(sni, baseDomain string) string {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	base := strings.ToLower(strings.TrimSuffix(baseDomain, "."))
	if sni == base || !strings.HasSuffix(sni, "."+base) {
		return ""
	}
	prefix := strings.TrimSuffix(sni, "."+base)
	if strings.Contains(prefix, ".") {
		return ""
	}
	return prefix
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIPFromRequest(r *http.Request) net.IP {
	// 仅在启用代理信任（TRUST_PROXY_HEADERS=true，部署于可信反代之后）时读取
	// X-Real-IP；否则使用 socket 对端地址，防止直连暴露时伪造来源 IP。
	if s.cfg.TrustProxyHeaders {
		if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
	}
	return nil
}

func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	body := http.MaxBytesReader(w, r.Body, max)
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func decodeBase64URL(s string) ([]byte, error) {
	// RFC 8484 §6: base64url, padding optional
	if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return d, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
