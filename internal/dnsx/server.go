package dnsx

import (
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
)

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

	udp *dns.Server
	tcp *dns.Server
	doh *http.Server
	doq *quic.Listener

	tlsConf *tls.Config

	lns  []net.Listener
	wg   sync.WaitGroup
	mu   sync.Mutex
	errs []error
}

func NewServer(cfg *config.Config, core *Core) (*Server, error) {
	s := &Server{cfg: cfg, core: core}

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
		// Per-connection tenant resolution by SNI prefix. Unknown prefixes
		// fail the handshake → the prefix inventory is never enumerable.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			prefix := prefixFromSNI(hello.ServerName, cfg.BaseDomain)
			if prefix == "" {
				// bare base domain or unrelated name: allow base-domain only
				if strings.EqualFold(hello.ServerName, cfg.BaseDomain) {
					return s.tlsConf.Clone(), nil
				}
				return nil, errors.New("unrecognized server name")
			}
			t, err := core.repos.TenantByPrefix(context.Background(), prefix)
			if err != nil || t == nil || !t.DoTEnabled {
				return nil, errors.New("unknown or disabled DoT prefix")
			}
			return s.tlsConf.Clone(), nil
		},
	}

	handler := dns.HandlerFunc(core.ServeDNS)
	s.udp = &dns.Server{Addr: cfg.DNSListenUDP, Net: "udp", Handler: handler, UDPSize: 4096}
	s.tcp = &dns.Server{Addr: cfg.DNSListenTCP, Net: "tcp", Handler: handler}

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
	if err := tc.Handshake(); err != nil {
		return
	}
	sni := tc.ConnectionState().ServerName
	meta := &RequestMeta{Via: "dot", SNI: sni}
	meta.Prefix = prefixFromSNI(sni, s.cfg.BaseDomain)
	if meta.Prefix != "" {
		if t, err := s.core.repos.TenantByPrefix(context.Background(), meta.Prefix); err == nil {
			meta.Tenant = t
		}
	}
	meta.ClientIP = clientIP(conn.RemoteAddr())

	// RFC 1035 TCP framing: 2-byte length + message, persistent connection.
	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(tc, hdr); err != nil {
			return
		}
		l := binary.BigEndian.Uint16(hdr)
		if l == 0 {
			return
		}
		body := make([]byte, l)
		if _, err := io.ReadFull(tc, body); err != nil {
			return
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			continue
		}
		resp, _ := s.core.Process(context.Background(), msg, meta)
		if resp == nil {
			continue
		}
		raw, err := resp.Pack()
		if err != nil {
			continue
		}
		out := make([]byte, 2+len(raw))
		binary.BigEndian.PutUint16(out, uint16(len(raw)))
		copy(out[2:], raw)
		tc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := tc.Write(out); err != nil {
			return
		}
	}
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
	if meta.Prefix != "" {
		if t, err := s.core.repos.TenantByPrefix(r.Context(), meta.Prefix); err == nil {
			meta.Tenant = t
		}
	}
	meta.ClientIP = clientIPFromRequest(r)

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
		go doqServeConn(context.Background(), conn, func(ctx context.Context, msg *dns.Msg, clientIP net.IP, meta *RequestMeta) *dns.Msg {
			meta.ClientIP = clientIP
			resp, _ := s.core.Process(ctx, msg, meta)
			return resp
		})
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

func clientIPFromRequest(r *http.Request) net.IP {
	// X-Real-IP is set by the local nginx (same-host proxy, see deploy/).
	if ip := net.ParseIP(r.Header.Get("X-Real-IP")); ip != nil {
		return ip
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
