package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

// impairment owns the same :0 socket for its entire lifetime. Once armed, it
// drops write 2 and swaps writes 4/5 below encryption, once, without retries.
type impairment struct {
	net.PacketConn
	mu              sync.Mutex
	armed           bool
	n, drops, swaps int
	held            []byte
	addr            net.Addr
	ready           chan struct{}
}

func (p *impairment) WriteTo(b []byte, a net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.armed {
		p.n++
		switch p.n {
		case 2:
			p.drops++
			return len(b), nil
		case 4:
			p.held = bytes.Clone(b)
			p.addr = a
			return len(b), nil
		case 5:
			n, e := p.PacketConn.WriteTo(b, a)
			if e != nil {
				return n, e
			}
			_, e = p.PacketConn.WriteTo(p.held, p.addr)
			p.held = nil
			p.swaps++
			close(p.ready)
			return n, e
		}
	}
	return p.PacketConn.WriteTo(b, a)
}

func TestCongestionTCPUDPSimultaneousSiblingIsolationAndImpairment(t *testing.T) {
	for _, mode := range []string{"reno", "bbr", "brutal", "force-brutal"} {
		t.Run(mode, func(t *testing.T) {
			material := testkit.TLS(t)
			pair, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
			if e != nil {
				t.Fatal(e)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(material.CACertificate))
			q := cfg.QUIC{Congestion: mode}
			if mode == "brutal" || mode == "force-brutal" {
				q.BrutalUp = "20mbps"
				q.BrutalDown = "100mbps"
			}
			packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			var streams, sessions atomic.Int64
			blocked := make(chan struct{})
			release := make(chan struct{})
			var slowOnce sync.Once
			s, e := NewServer(context.Background(), packet, ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, Transport: cfg.Hysteria{Version: 2, QUIC: q}, Authenticate: func(p string) (string, bool) { return p, p == "A" }, TCP: func(ctx context.Context, id string, s *Stream, dst access.Endpoint) error {
				if id != "A" {
					t.Error("TCP auth")
				}
				if dst.Port == 1 {
					return wire.ErrRejected
				}
				streams.Add(1)
				defer streams.Add(-1)
				if e := s.Reply(true); e != nil {
					return e
				}
				if dst.Port == 2 {
					slowOnce.Do(func() { close(blocked) })
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				_, e := io.Copy(s, s)
				return e
			}, UDP: func(ctx context.Context, id string, p net.PacketConn) error {
				if id != "A" {
					t.Error("UDP auth")
				}
				sessions.Add(1)
				defer sessions.Add(-1)
				b := make([]byte, 4096)
				for {
					n, a, e := p.ReadFrom(b)
					if e != nil {
						return e
					}
					if _, e = p.WriteTo(b[:n], a); e != nil {
						return e
					}
				}
			}})
			if e != nil {
				t.Fatal(e)
			}
			s.Start()
			defer s.Close(context.Background())
			base, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			imp := &impairment{PacketConn: base, ready: make(chan struct{})}
			var created atomic.Int64
			c, e := NewClient(context.Background(), ClientConfig{TLS: &tls.Config{RootCAs: pool, ServerName: material.ServerName}, Password: "A", Transport: cfg.Hysteria{Version: 2, QUIC: q}, Socket: func(context.Context) (net.PacketConn, net.Addr, error) {
				created.Add(1)
				return imp, packet.LocalAddr(), nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			slow, e := c.OpenTCP(context.Background(), access.Endpoint{Host: "localhost", Port: 2})
			if e != nil {
				t.Fatal(e)
			}
			defer slow.Close()
			<-blocked
			imp.mu.Lock()
			imp.armed = true
			imp.mu.Unlock()
			var wg sync.WaitGroup
			for i := range 8 {
				wg.Go(func() {
					stream, e := c.OpenTCP(context.Background(), access.Endpoint{Host: "localhost", Port: 443})
					if e != nil {
						t.Error(e)
						return
					}
					defer stream.Close()
					stream.SetDeadline(time.Now().Add(15 * time.Second))
					want := bytes.Repeat([]byte{byte(i), 31, 0}, (1<<20)/3+1)
					done := make(chan error, 1)
					go func() {
						_, e := stream.Write(want)
						if e == nil {
							e = stream.(interface{ CloseWrite() error }).CloseWrite()
						}
						done <- e
					}()
					got, e := io.ReadAll(stream)
					if e != nil || !bytes.Equal(got, want) {
						t.Error("TCP under loss/reorder", e)
					}
					if e = <-done; e != nil {
						t.Error(e)
					}
				})
			}
			// Streams are held by the slow sibling for the entire UDP exercise.
			for range 2 {
				wg.Go(func() {
					select {
					case <-imp.ready:
					case <-time.After(15 * time.Second):
						t.Error("carrier schedule stalled")
						return
					}
					p, e := c.OpenPacket(context.Background(), access.Endpoint{Host: "localhost", Port: 443})
					if e != nil {
						t.Error(e)
						return
					}
					defer p.Close()
					p.SetDeadline(time.Now().Add(15 * time.Second))
					for _, size := range []int{1, 900, 4096} {
						want := bytes.Repeat([]byte{51}, size)
						if _, e = p.WriteTo(want, nil); e != nil {
							t.Error(e)
							return
						}
						got := make([]byte, 4096)
						n, _, e := p.ReadFrom(got)
						if e != nil || !bytes.Equal(want, got[:n]) {
							t.Error("UDP alongside TCP", e)
							return
						}
					}
				})
			}
			if failed, e := c.OpenTCP(context.Background(), access.Endpoint{Host: "localhost", Port: 1}); e == nil {
				failed.Close()
				t.Error("failed target accepted")
			}
			wg.Wait()
			close(release)
			slow.Close()
			if created.Load() != 1 {
				t.Fatal("reuse", created.Load())
			}
			imp.mu.Lock()
			drops, swaps := imp.drops, imp.swaps
			imp.mu.Unlock()
			if drops != 1 || swaps != 1 {
				t.Fatal("impairment not applied", drops, swaps)
			}
			for _, state := range append(c.Congestion(), s.Congestion()...) {
				if mode != "reno" && (state.Model.Algorithm == "" || state.Model.Sent == 0 || state.Model.Acked == 0) {
					t.Fatal("inactive controller", state)
				}
				t.Logf("actual controller %+v", state)
			}
			c.Close()
			s.Close(context.Background())
			if streams.Load() != 0 || sessions.Load() != 0 || c.manager.ActiveConnections() != 0 {
				t.Fatal("resource baseline", streams.Load(), sessions.Load())
			}
		})
	}
}
