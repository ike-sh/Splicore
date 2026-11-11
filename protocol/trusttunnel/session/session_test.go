package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

func startServer(t *testing.T, mode string, configure func(*ServerConfig)) (string, *tls.Config, *Server) {
	return startServerAt(t, mode, "127.0.0.1:0", configure)
}
func startServerAt(t *testing.T, mode, listen string, configure func(*ServerConfig)) (string, *tls.Config, *Server) {
	t.Helper()
	settings := testkit.TLS(t)
	cert, _ := os.ReadFile(settings.CertificateFile)
	key, _ := os.ReadFile(settings.PrivateKeyFile)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(settings.CACertificate))
	tc := &tls.Config{ServerName: settings.ServerName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	cfg := ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, HTTP2: mode == "http2", HTTP3: mode == "http3", Authenticate: func(u, p string) (string, bool) {
		if (u == "alpha" && p == "alpha-pass") || (u == "beta" && p == "beta-pass") {
			return u, true
		}
		return "", false
	}, DialTCP: func(ctx context.Context, _ string, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", a)
	}, DialUDP: func(ctx context.Context, _ string, a string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", a)
	}, Relay: func(ctx context.Context, _ string, a, b net.Conn) { relay.Join(ctx, a, b) }, Echo: func(ctx context.Context, _ string, r wire.EchoRequest) (wire.EchoReply, error) {
		kind := uint8(0)
		if r.Destination.Is6() {
			kind = 129
		}
		return wire.EchoReply{ID: r.ID, Source: r.Destination, Sequence: r.Sequence, Type: kind}, nil
	}}
	if configure != nil {
		configure(&cfg)
	}
	s, e := NewServer(cfg)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	var address string
	if mode == "http3" {
		p, e := net.ListenPacket("udp", listen)
		if e != nil {
			t.Fatal(e)
		}
		address = p.LocalAddr().String()
		go func() { defer close(done); _ = s.ServeUDP(p) }()
		t.Cleanup(func() { _ = p.Close() })
	} else {
		l, e := net.Listen("tcp", listen)
		if e != nil {
			t.Fatal(e)
		}
		address = l.Addr().String()
		go func() { defer close(done); _ = s.ServeTCP(l) }()
		t.Cleanup(func() { _ = l.Close() })
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := s.Close(ctx); e != nil {
			t.Error(e)
		}
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("serve leak")
		}
	})
	return address, tc, s
}
func newClient(t *testing.T, mode, address string, tc *tls.Config, configure func(*ClientConfig)) *Client {
	t.Helper()
	cfg := ClientConfig{Mode: mode, Addresses: []string{address}, Username: "alpha", Password: "alpha-pass", TLS: tc, DialTCP: (&net.Dialer{}).DialContext, PacketSocket: func(ctx context.Context, a string) (net.PacketConn, net.Addr, error) {
		r, e := net.ResolveUDPAddr("udp", a)
		if e != nil {
			return nil, nil, e
		}
		network, local := "udp4", "127.0.0.1:0"
		if r.IP.To4() == nil {
			network, local = "udp6", "[::1]:0"
		}
		p, e := net.ListenPacket(network, local)
		return p, r, e
	}}
	if configure != nil {
		configure(&cfg)
	}
	c, e := NewClient(cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func tcpEcho(t *testing.T, network, address string) string {
	t.Helper()
	l, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := make(map[net.Conn]bool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
		mu.Lock()
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr().String()
}
func udpEcho(t *testing.T, network, address string) netip.AddrPort {
	t.Helper()
	p, e := net.ListenPacket(network, address)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = p.Close(); <-done })
	return p.LocalAddr().(*net.UDPAddr).AddrPort()
}
func transfer(c *Client, target string, size int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, e := c.Open(ctx, target)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte("TrustTunnel native integrity\x00"), 1+size/29)[:size]
	write := make(chan error, 1)
	go func() {
		_, e := conn.Write(payload)
		if e == nil {
			e = conn.(interface{ CloseWrite() error }).CloseWrite()
		}
		write <- e
	}()
	received, e := io.ReadAll(conn)
	we := <-write
	if e != nil {
		return fmt.Errorf("TCP response bytes=%d expected=%d: %w", len(received), size, e)
	}
	if we != nil {
		return we
	}
	if len(received) != len(payload) || subtle.ConstantTimeCompare(received, payload) != 1 {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func TestTCPUDPEchoHealth(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			a, tc, _ := startServer(t, mode, nil)
			var dials atomic.Int64
			c := newClient(t, mode, a, tc, func(cfg *ClientConfig) {
				dial := cfg.DialTCP
				cfg.DialTCP = func(ctx context.Context, n, a string) (net.Conn, error) { dials.Add(1); return dial(ctx, n, a) }
				packet := cfg.PacketSocket
				cfg.PacketSocket = func(ctx context.Context, a string) (net.PacketConn, net.Addr, error) {
					dials.Add(1)
					return packet(ctx, a)
				}
			})
			target := tcpEcho(t, "tcp", "127.0.0.1:0")
			for _, size := range []int{0, 1, 16 << 10, 64 << 10, 1 << 20, 4 << 20} {
				if e := transfer(c, target, size); e != nil {
					t.Fatal(size, e)
				}
			}
			targetUDP := udpEcho(t, "udp4", "127.0.0.1:0")
			for i := range 8 {
				p, e := c.OpenPacket(context.Background(), targetUDP)
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
				_ = p.SetDeadline(time.Now().Add(5 * time.Second))
				for _, size := range []int{0, 1, 53, 1200, 1350, 1472, 4048} {
					b := bytes.Repeat([]byte{byte(i)}, size)
					if _, e = p.WriteTo(b, net.UDPAddrFromAddrPort(targetUDP)); e != nil {
						t.Fatal(e)
					}
					buf := make([]byte, 65535)
					n, from, e := p.ReadFrom(buf)
					if e != nil || from.String() != targetUDP.String() || sha256.Sum256(b) != sha256.Sum256(buf[:n]) {
						t.Fatal(size, e)
					}
				}
			}
			var wg sync.WaitGroup
			errors := make(chan error, 128)
			for range 128 {
				wg.Add(1)
				go func() { defer wg.Done(); errors <- transfer(c, target, 16384) }()
			}
			wg.Wait()
			close(errors)
			for e := range errors {
				if e != nil {
					t.Fatal(e)
				}
			}
			for range 10 {
				if e := c.Check(context.Background()); e != nil {
					t.Fatal(e)
				}
			}
			for _, ip := range []string{"127.0.0.1", "::1"} {
				r, e := c.Echo(context.Background(), wire.EchoRequest{ID: 53, Destination: netip.MustParseAddr(ip), Sequence: 4, TTL: 64, DataSize: 4048})
				if e != nil || r.ID != 53 || r.Sequence != 4 {
					t.Fatal(e)
				}
			}
			if dials.Load() != 1 {
				t.Fatal("session not reused", dials.Load())
			}
			t.Log("payload TCP sizes=6 UDP flows=8 UDP sizes=7 concurrent_TCP=128 ICMP=mock_only sessions=1")
		})
	}
}
func TestAuthenticationTLSAndNoDirect(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			var targets atomic.Int64
			a, tc, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { targets.Add(1); return nil, io.ErrClosedPipe }
			})
			for _, credential := range []struct{ u, p string }{{"wrong", "alpha-pass"}, {"alpha", "wrong"}} {
				c := newClient(t, mode, a, tc, func(cfg *ClientConfig) { cfg.Username = credential.u; cfg.Password = credential.p })
				if _, e := c.Open(context.Background(), "127.0.0.1:1"); !IsCode(e, Auth) {
					t.Fatal(e)
				}
				if _, e := c.Open(context.Background(), "127.0.0.1:1"); !IsCode(e, Auth) {
					t.Fatal("unsafe auth recovery", e)
				}
			}
			bad := tc.Clone()
			bad.ServerName = "mismatch.invalid"
			c := newClient(t, mode, a, bad, nil)
			if _, e := c.Open(context.Background(), "127.0.0.1:1"); !IsCode(e, Certificate) {
				t.Fatal(e)
			}
			if targets.Load() != 0 {
				t.Fatal("dial before auth or direct bypass")
			}
		})
	}
}
