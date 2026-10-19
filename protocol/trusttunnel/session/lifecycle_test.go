package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"golang.org/x/net/http2"
)

func TestH2InitialWindowOnWire(t *testing.T) {
	var pair tls.Certificate
	a, tc, s := startServer(t, "http2", func(c *ServerConfig) { pair = c.TLS.Certificates[0] })
	_ = a
	_ = s
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	observed := make(chan uint32, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, e := l.Accept()
		if e != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2"}})
		if conn.Handshake() != nil {
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, e := io.ReadFull(conn, preface); e != nil || string(preface) != http2.ClientPreface {
			return
		}
		f := http2.NewFramer(conn, conn)
		frame, e := f.ReadFrame()
		if e != nil {
			return
		}
		settings, ok := frame.(*http2.SettingsFrame)
		if !ok {
			return
		}
		_ = settings.ForeachSetting(func(v http2.Setting) error {
			if v.ID == http2.SettingInitialWindowSize {
				observed <- v.Val
			}
			return nil
		})
		_ = f.WriteSettings()
		_ = f.WriteSettingsAck()
	}()
	cfg := ClientConfig{TLS: tc, DialTCP: (&net.Dialer{}).DialContext}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, e := newH2(ctx, ctx, cfg, l.Addr().String())
	if raw != nil {
		defer raw.close()
	}
	if e != nil {
		t.Fatal(e)
	}
	select {
	case n := <-observed:
		if n != 131072 {
			t.Fatal(n)
		}
	case <-ctx.Done():
		t.Fatal("no SETTINGS")
	}
	<-done
}
func TestAutoSelectionWinnerAndLoserOwnership(t *testing.T) {
	if !H3Enabled() {
		t.Skip("with_quic required")
	}
	for _, winner := range []string{"http2", "http3"} {
		t.Run(winner, func(t *testing.T) {
			address, tc, _ := startServer(t, winner, nil)
			c := newClient(t, "auto", address, tc, func(cfg *ClientConfig) {
				cfg.FallbackDelay = 5 * time.Millisecond
				cfg.HealthTimeout = time.Second
				if winner == "http2" {
					cfg.PacketSocket = func(ctx context.Context, a string) (net.PacketConn, net.Addr, error) {
						p, e := net.ListenPacket("udp4", "127.0.0.1:0")
						if e != nil {
							return nil, nil, e
						}
						remote, _ := net.ResolveUDPAddr("udp", a)
						return p, remote, nil
					}
				} else {
					cfg.DialTCP = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
				}
			})
			if e := c.Check(context.Background()); e != nil {
				t.Fatal(e)
			}
			c.mu.Lock()
			mode := c.session.mode
			c.mu.Unlock()
			if mode != winner {
				t.Fatal(mode)
			}
			if c.State() != Ready {
				t.Fatal(c.State())
			}
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			if c.State() != ClosedState {
				t.Fatal(c.State())
			}
		})
	}
}
func TestReservedAbuseAndAuthenticationBeforeDial(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			var dials atomic.Int64
			a, tc, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.DialTCP = func(context.Context, string, string) (net.Conn, error) { dials.Add(1); return nil, io.EOF }
			})
			c := newClient(t, mode, a, tc, nil)
			s, e := c.acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			for _, target := range []string{"_UDP2", "_udp2:443", "_check:0", "host:0", "a@b:443"} {
				stream, e := s.raw.open(context.Background(), target, c.headers(target))
				if stream != nil {
					stream.Close()
				}
				if e == nil {
					t.Fatal(target)
				}
			}
			for _, auth := range [][]string{nil, {"Basic ?"}, {wire.Authorization("alpha", "wrong")}, {wire.Authorization("alpha", "alpha-pass"), wire.Authorization("alpha", "alpha-pass")}} {
				h := c.headers("_check")
				if auth == nil {
					h.Del("Proxy-Authorization")
				} else {
					h["Proxy-Authorization"] = auth
				}
				if raw, e := s.raw.open(context.Background(), "127.0.0.1:1", h); e == nil {
					raw.Close()
					t.Fatal("auth accepted")
				}
			}
			first, e := c.openSession(context.Background(), s, "_udp2")
			if e != nil {
				t.Fatal(e)
			}
			defer first.Close()
			if raw, e := s.raw.open(context.Background(), "_udp2", c.headers("_udp2")); e == nil {
				raw.Close()
				t.Fatal("duplicate UDP stream")
			}
			if dials.Load() != 0 {
				t.Fatal("unauthenticated/invalid target dial")
			}
		})
	}
}
func TestRecoveryAndSessionShutdown(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			a, tc, _ := startServer(t, mode, nil)
			c := newClient(t, mode, a, tc, func(cfg *ClientConfig) {
				cfg.RecoveryInitial = 5 * time.Millisecond
				cfg.RecoveryCap = 20 * time.Millisecond
			})
			target := tcpEcho(t, "tcp4", "127.0.0.1:0")
			if e := transfer(c, target, 4096); e != nil {
				t.Fatal(e)
			}
			c.mu.Lock()
			old := c.session
			c.mu.Unlock()
			old.raw.close()
			c.invalidate(old, failure(Unavailable, nil))
			if c.State() != Recovering {
				t.Fatal(c.State())
			}
			if e := transfer(c, target, 4096); e != nil {
				t.Fatal(e)
			}
			c.mu.Lock()
			fresh := c.session
			c.mu.Unlock()
			if fresh == old {
				t.Fatal("reused dead session")
			}
			if e := c.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e := c.Open(context.Background(), target); !IsCode(e, Closed) {
				t.Fatal(e)
			}
		})
	}
}
func TestHealthCoalescesAndEndpointDataSatisfiesCheck(t *testing.T) {
	a, tc, _ := startServer(t, "http2", nil)
	c := newClient(t, "http2", a, tc, nil)
	if e := c.Check(context.Background()); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for range 100 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- c.Check(context.Background()) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	s.mu.Lock()
	flight := &healthFlight{cancel: func() {}}
	s.check = flight
	s.mu.Unlock()
	s.received()
	s.mu.Lock()
	if !flight.data {
		t.Fatal("data did not satisfy liveness")
	}
	s.check = nil
	s.mu.Unlock()
}
func TestBoundedFramingAndMuxExpiry(t *testing.T) {
	a, tc, _ := startServer(t, "http2", func(cfg *ServerConfig) { cfg.MaxFlows = 1; cfg.UDPIdleTimeout = 10 * time.Millisecond })
	c := newClient(t, "http2", a, tc, func(cfg *ClientConfig) { cfg.MaxFlows = 1; cfg.UDPIdleTimeout = 10 * time.Millisecond })
	target := udpEcho(t, "udp4", "127.0.0.1:0")
	p, e := c.OpenPacket(context.Background(), target)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.OpenPacket(context.Background(), target); !IsCode(e, Capacity) {
		t.Fatal("flow bound", e)
	}
	buf := []byte("expiry")
	if _, e = p.WriteTo(buf, net.UDPAddrFromAddrPort(target)); e != nil {
		t.Fatal(e)
	}
	received := make([]byte, 32)
	_ = p.SetReadDeadline(time.Now().Add(time.Second))
	n, _, e := p.ReadFrom(received)
	if e != nil || !bytes.Equal(buf, received[:n]) {
		t.Fatal(e)
	}
	_ = p.SetReadDeadline(time.Time{})
	_, _, e = p.ReadFrom(received)
	if !IsCode(e, Unavailable) {
		t.Fatal("idle flow retained", e)
	}
	p.Close()
	p, e = c.OpenPacket(context.Background(), target)
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
}
func TestRepeatedOwnedResources(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			a, tc, _ := startServer(t, mode, nil)
			target := tcpEcho(t, "tcp4", "127.0.0.1:0")
			warm := newClient(t, mode, a, tc, nil)
			if e := transfer(warm, target, 4096); e != nil {
				t.Fatal(e)
			}
			warm.Close()
			runtime.GC()
			before := runtime.NumGoroutine()
			fds, _ := os.ReadDir("/proc/self/fd")
			for range 20 {
				c := newClient(t, mode, a, tc, nil)
				if e := transfer(c, target, 4096); e != nil {
					t.Fatal(e)
				}
				c.Close()
			}
			runtime.GC()
			deadline := time.Now().Add(time.Second)
			for {
				after, _ := os.ReadDir("/proc/self/fd")
				g := runtime.NumGoroutine()
				if g <= before+2 && len(after) <= len(fds) {
					t.Logf("20 cycles goroutines %d->%d fd %d->%d", before, g, len(fds), len(after))
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("resource growth goroutines %d->%d fd %d->%d", before, g, len(fds), len(after))
				}
				runtime.Gosched()
			}
		})
	}
}
