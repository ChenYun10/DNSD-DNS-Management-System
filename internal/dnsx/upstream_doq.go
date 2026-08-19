package dnsx

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"dns-platform/internal/config"
	"dns-platform/internal/model"
)

// DoQ upstream client (RFC 9250): DNS messages framed with a 2-byte length
// prefix, one query per bidirectional QUIC stream.
type doqClient struct {
	cfg  *config.Config
	up   *model.Upstream
	addr string

	mu     sync.Mutex
	conn   *quic.Conn
	connAt time.Time
}

func newDoQClient(cfg *config.Config, u *model.Upstream, addr string) *doqClient {
	return &doqClient{cfg: cfg, up: u, addr: addr}
}

func (c *doqClient) String() string { return fmt.Sprintf("doq://%s", c.addr) }

func (c *doqClient) getConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil && time.Since(c.connAt) < 60*time.Second && c.conn.Context().Err() == nil {
		return c.conn, nil
	}
	tlsCfg := tlsConfigForUpstream(c.cfg, c.up)
	tlsCfg.NextProtos = []string{"doq"}
	qcfg := &quic.Config{
		MaxIdleTimeout:       2 * time.Minute,
		HandshakeIdleTimeout: c.cfg.UpstreamTimeout,
	}
	conn, err := quic.DialAddr(ctx, c.addr, tlsCfg, qcfg)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.connAt = time.Now()
	return c.conn, nil
}

func (c *doqClient) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	raw, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if len(raw) > 65535 {
		return nil, fmt.Errorf("message too large for DoQ: %d bytes", len(raw))
	}
	// 2-byte big-endian length prefix + message
	buf := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(buf, uint16(len(raw)))
	copy(buf[2:], raw)
	if _, err := stream.Write(buf); err != nil {
		return nil, err
	}
	stream.Close() // half-close: server reads request, then responds

	// read 2-byte length
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(stream, hdr); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(hdr)
	if length == 0 {
		return nil, fmt.Errorf("empty DoQ response")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(stream, body); err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *doqClient) HealthProbe(ctx context.Context) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(c.cfg.HealthDomain), dns.TypeA)
	_, err := c.Exchange(ctx, m)
	return err
}

// ---------------------------------------------------------------------------
// Downstream DoQ listener helpers (RFC 9250 server side)
// ---------------------------------------------------------------------------

// doqServeConn handles one QUIC connection: each client stream carries exactly
// one query (2-byte length + message); we respond and close the stream.
func doqServeConn(ctx context.Context, conn *quic.Conn, process func(ctx context.Context, msg *dns.Msg, clientIP net.IP, meta *RequestMeta) *dns.Msg) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(s *quic.Stream) {
			defer s.Close()
			msg, ok := readDoQMsg(s)
			if !ok {
				return
			}
			clientIP := conn.RemoteAddr()
			var ip net.IP
			if ta, ok := clientIP.(*net.UDPAddr); ok {
				ip = ta.IP
			} else if ta, ok := clientIP.(*net.TCPAddr); ok {
				ip = ta.IP
			}
			resp := process(ctx, msg, ip, &RequestMeta{Via: "doq"})
			if resp == nil {
				return
			}
			raw, err := resp.Pack()
			if err != nil || len(raw) > 65535 {
				return
			}
			buf := make([]byte, 2+len(raw))
			binary.BigEndian.PutUint16(buf, uint16(len(raw)))
			copy(buf[2:], raw)
			s.Write(buf)
		}(stream)
	}
}

func readDoQMsg(r io.Reader) (*dns.Msg, bool) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, false
	}
	length := binary.BigEndian.Uint16(hdr)
	if length == 0 {
		return nil, false
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, false
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, false
	}
	return m, true
}
