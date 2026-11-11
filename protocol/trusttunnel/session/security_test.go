package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

// Locally generated root/intermediate/leaf chains exercise actual TLS handshakes
// without an external CA service or modification of the system trust store.
func certificateFixture(t *testing.T, expired, selfSigned, missingIntermediate bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	makeCert := func(serial int64, ca bool) (*x509.Certificate, ed25519.PrivateKey) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "trusttunnel.test"}, DNSNames: []string{"trusttunnel.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, key
	}
	root, rk := makeCert(1, true)
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rk.Public(), rk)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rootDER)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if selfSigned {
		return tls.Certificate{Certificate: [][]byte{rootDER}, PrivateKey: rk}, pool
	}
	inter, ik := makeCert(2, true)
	interDER, e := x509.CreateCertificate(rand.Reader, inter, root, ik.Public(), rk)
	if e != nil {
		t.Fatal(e)
	}
	inter, _ = x509.ParseCertificate(interDER)
	leaf, lk := makeCert(3, false)
	if expired {
		leaf.NotBefore = time.Now().Add(-2 * time.Hour)
		leaf.NotAfter = time.Now().Add(-time.Hour)
	}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, inter, lk.Public(), ik)
	if e != nil {
		t.Fatal(e)
	}
	chain := [][]byte{leafDER, interDER}
	if missingIntermediate {
		chain = chain[:1]
	}
	return tls.Certificate{Certificate: chain, PrivateKey: lk}, pool
}

func TestTLSChainAndEndpointMatrix(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		for _, name := range []string{"ca-chain", "self-signed-trusted", "wrong-ca", "unknown-ca", "expired", "missing-intermediate", "hostname-mismatch", "IPv6-endpoint", "hostname-endpoint"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				pair, pool := certificateFixture(t, name == "expired", name == "self-signed-trusted", name == "missing-intermediate")
				listen := "127.0.0.1:0"
				if name == "IPv6-endpoint" {
					listen = "[::1]:0"
				}
				a, _, _ := startServerAt(t, mode, listen, func(cfg *ServerConfig) { cfg.TLS = &tls.Config{Certificates: []tls.Certificate{pair}} })
				tc := &tls.Config{ServerName: "trusttunnel.test", RootCAs: pool}
				if name == "wrong-ca" {
					_, tc.RootCAs = certificateFixture(t, false, false, false)
				}
				if name == "unknown-ca" {
					tc.RootCAs = x509.NewCertPool()
				}
				if name == "hostname-mismatch" {
					tc.ServerName = "wrong.test"
				}
				if name == "hostname-endpoint" {
					_, port, _ := net.SplitHostPort(a)
					a = net.JoinHostPort("localhost", port)
				}
				c := newClient(t, mode, a, tc, nil)
				e := c.Check(context.Background())
				bad := name == "wrong-ca" || name == "unknown-ca" || name == "expired" || name == "missing-intermediate" || name == "hostname-mismatch"
				if bad && !IsCode(e, Certificate) || !bad && e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}

func TestStreamDeadlineBackpressureTailAndSibling(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			blocked := make(chan struct{})
			a, tc, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.DialTCP = func(ctx context.Context, _ string, target string) (net.Conn, error) {
					x, y := net.Pipe()
					if target == "stall.test:443" {
						t.Cleanup(func() { _ = y.Close() })
						close(blocked)
					} else {
						go func() {
							defer y.Close()
							b := make([]byte, 4)
							if _, e := io.ReadFull(y, b); e == nil {
								_, _ = y.Write(append(b, bytes.Repeat([]byte{0x61}, 100000)...))
							}
						}()
					}
					return x, nil
				}
			})
			c := newClient(t, mode, a, tc, nil)
			stall, e := c.Open(context.Background(), "stall.test:443")
			if e != nil {
				t.Fatal(e)
			}
			<-blocked
			write := make(chan error, 1)
			go func() { _, e := stall.Write(make([]byte, 16<<20)); write <- e }()
			// A sibling must still complete while the first stream exhausts its window.
			sibling, e := c.Open(context.Background(), "tail.test:443")
			if e != nil {
				t.Fatal(e)
			}
			_ = sibling.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = sibling.Write([]byte("tail")); e != nil {
				t.Fatal(e)
			}
			tail, e := io.ReadAll(sibling)
			if e != nil || len(tail) != 100004 || string(tail[:4]) != "tail" {
				t.Fatal(len(tail), e)
			}
			_ = sibling.Close()
			// Moving the deadline after Write started must interrupt the active writer.
			_ = stall.SetWriteDeadline(time.Now())
			select {
			case e := <-write:
				if !errors.Is(e, os.ErrDeadlineExceeded) {
					t.Fatal(e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("write deadline swallowed")
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() { defer wg.Done(); _ = stall.Close() }()
			}
			wg.Wait()
			if e = c.Check(context.Background()); e != nil {
				t.Fatal("sibling reset damaged session", e)
			}
		})
	}
}

func TestEchoLateReplyIsolationAndMuxRecreation(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			first := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int32
			a, tc, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.Echo = func(ctx context.Context, _ string, r wire.EchoRequest) (wire.EchoReply, error) {
					if calls.Add(1) == 1 {
						close(first)
						select {
						case <-release:
						case <-ctx.Done():
							return wire.EchoReply{}, ctx.Err()
						}
					}
					return wire.EchoReply{ID: r.ID, Sequence: r.Sequence, Source: r.Destination}, nil
				}
			})
			c := newClient(t, mode, a, tc, nil)
			r := wire.EchoRequest{ID: 8, Sequence: 9, Destination: netip.MustParseAddr("192.0.2.1"), TTL: 64, DataSize: 32}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, e := c.Echo(ctx, r); done <- e }()
			<-first
			cancel()
			if e := <-done; !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			// The old reply is released only after the second request has its own wire key.
			go func() {
				reply, e := c.Echo(context.Background(), r)
				if e == nil && (reply.ID != r.ID || reply.Sequence != r.Sequence) {
					e = io.ErrUnexpectedEOF
				}
				done <- e
			}()
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			close(release)
			c.mu.Lock()
			s := c.session
			c.mu.Unlock()
			s.mu.Lock()
			old := s.echo
			s.mu.Unlock()
			old.cancel()
			deadline := time.Now().Add(5 * time.Second)
			for {
				s.mu.Lock()
				cleared := s.echo == nil
				s.mu.Unlock()
				if cleared {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("dead echo retained")
				}
				time.Sleep(time.Millisecond)
			}
			if _, e := c.Echo(context.Background(), r); e != nil {
				t.Fatal("echo recreation", e)
			}
		})
	}
}

type healthPeer struct {
	openFn func(context.Context) (net.Conn, error)
}

func (h healthPeer) open(ctx context.Context, _ string, _ http.Header) (net.Conn, error) {
	return h.openFn(ctx)
}
func (healthPeer) alive() bool  { return true }
func (healthPeer) close() error { return nil }

func TestHealthTimeoutAuthDataAndClose(t *testing.T) {
	for _, scenario := range []string{"timeout", "auth", "endpoint-data", "close"} {
		t.Run(scenario, func(t *testing.T) {
			a, tc, _ := startServer(t, "http2", nil)
			c := newClient(t, "http2", a, tc, func(cfg *ClientConfig) { cfg.HealthTimeout = 30 * time.Millisecond })
			life, closeSession := context.WithCancel(c.ctx)
			s := &clientSession{ctx: life, cancel: closeSession, streams: map[*clientStream]bool{}}
			started := make(chan struct{})
			s.raw = healthPeer{func(ctx context.Context) (net.Conn, error) {
				close(started)
				if scenario == "auth" {
					return nil, status(407)
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			s.lastRx.Store(time.Now().UnixNano())
			s.lastUse.Store(time.Now().UnixNano())
			c.mu.Lock()
			c.session = s
			c.mu.Unlock()
			done := make(chan error, 1)
			go func() { done <- c.Check(context.Background()) }()
			<-started
			if scenario == "endpoint-data" {
				s.received()
			}
			if scenario == "close" {
				c.Close()
			}
			e := <-done
			switch scenario {
			case "timeout":
				if !IsCode(e, HealthTimeout) {
					t.Fatal(e)
				}
			case "auth":
				if !IsCode(e, Auth) {
					t.Fatal(e)
				}
			case "endpoint-data":
				if e != nil {
					t.Fatal(e)
				}
			case "close":
				if e == nil {
					t.Fatal("close looked healthy")
				}
			}
		})
	}
}

func TestPacketActiveWriteDeadlineAndClose(t *testing.T) {
	for _, scenario := range []string{"deadline", "close"} {
		t.Run(scenario, func(t *testing.T) {
			x, y := net.Pipe()
			defer y.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stop := context.AfterFunc(ctx, func() { x.Close() })
			defer stop()
			m := &udpMux{conn: x, ctx: ctx, cancel: cancel, c: &Client{config: ClientConfig{ConnectTimeout: time.Second, MaxFlows: 4}}, flows: map[netip.AddrPort]*Packet{}, gate: make(chan struct{}, 1), writes: make(chan struct{}, 64)}
			m.gate <- struct{}{}
			target := netip.MustParseAddrPort("192.0.2.1:53")
			packet, e := m.open(target)
			if e != nil {
				t.Fatal(e)
			}
			p := packet.(*Packet)
			done := make(chan error, 1)
			go func() { _, e := p.WriteTo([]byte("blocked"), net.UDPAddrFromAddrPort(target)); done <- e }()
			// Reading the frame header proves the writer is active without draining it.
			b := make([]byte, 4)
			if _, e = io.ReadFull(y, b); e != nil {
				t.Fatal(e)
			}
			if scenario == "deadline" {
				p.SetWriteDeadline(time.Now())
			} else {
				p.Close()
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("blocked write succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("blocked packet writer retained")
			}
			x.Close()
			p.Close()
		})
	}
}
