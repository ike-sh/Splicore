package session

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestSelectionSecurityFailureAddressFailoverAndClose(t *testing.T) {
	if !H3Enabled() {
		t.Skip("with_quic required")
	}
	for _, scenario := range []string{"both-fail", "H3-immediate-failure", "auth-terminal", "certificate-terminal", "multiple-addresses", "close-race", "near-simultaneous"} {
		t.Run(scenario, func(t *testing.T) {
			var pair tls.Certificate
			a, tc, _ := startServer(t, "http2", func(cfg *ServerConfig) { pair = cfg.TLS.Certificates[0] })
			b, _, _ := startServer(t, "http3", func(cfg *ServerConfig) { cfg.TLS.Certificates = []tls.Certificate{pair} })
			both := make(chan struct{})
			var arrivals atomic.Int32
			arrive := func() {
				if arrivals.Add(1) == 2 {
					close(both)
				}
			}
			var h2Calls atomic.Int32
			c := newClient(t, "auto", b, tc, func(cfg *ClientConfig) {
				cfg.Addresses = []string{b, a}
				cfg.FallbackDelay = time.Millisecond
				if scenario == "auth-terminal" {
					cfg.Password = "wrong"
					cfg.FallbackDelay = time.Second
				}
				if scenario == "certificate-terminal" {
					cfg.TLS = tc.Clone()
					cfg.TLS.ServerName = "wrong.test"
					cfg.FallbackDelay = time.Second
				}
				dial := cfg.DialTCP
				cfg.DialTCP = func(ctx context.Context, n, address string) (net.Conn, error) {
					h2Calls.Add(1)
					if scenario == "close-race" {
						arrive()
						<-ctx.Done()
						return nil, ctx.Err()
					}
					if scenario == "near-simultaneous" && address == a {
						arrive()
						select {
						case <-both:
						case <-ctx.Done():
							return nil, ctx.Err()
						}
					}
					if scenario == "both-fail" {
						return nil, io.ErrClosedPipe
					}
					return dial(ctx, n, address)
				}
				packet := cfg.PacketSocket
				cfg.PacketSocket = func(ctx context.Context, address string) (net.PacketConn, net.Addr, error) {
					if scenario == "close-race" {
						arrive()
						<-ctx.Done()
						return nil, nil, ctx.Err()
					}
					if scenario == "near-simultaneous" && address == b {
						arrive()
						select {
						case <-both:
						case <-ctx.Done():
							return nil, nil, ctx.Err()
						}
					}
					if scenario == "both-fail" || scenario == "H3-immediate-failure" {
						return nil, nil, io.ErrClosedPipe
					}
					return packet(ctx, address)
				}
				if scenario == "multiple-addresses" {
					cfg.Mode = "http2"
					cfg.DialTCP = func(ctx context.Context, n, address string) (net.Conn, error) {
						if address == b {
							return nil, io.ErrClosedPipe
						}
						return dial(ctx, n, address)
					}
				}
			})
			var e error
			if scenario == "close-race" {
				done := make(chan error, 1)
				go func() { done <- c.Check(context.Background()) }()
				select {
				case <-both:
				case <-time.After(5 * time.Second):
					t.Fatal("race did not start")
				}
				c.Close()
				e = <-done
			} else {
				e = c.Check(context.Background())
			}
			switch scenario {
			case "auth-terminal", "certificate-terminal":
				code := Auth
				if scenario == "certificate-terminal" {
					code = Certificate
				}
				if !IsCode(e, code) || h2Calls.Load() != 0 {
					t.Fatal("security fallback", e, h2Calls.Load())
				}
			case "both-fail", "close-race":
				if e == nil {
					t.Fatal("failed race published READY")
				}
			default:
				if e != nil {
					t.Fatal(e)
				}
				if c.State() != Ready {
					t.Fatal(c.State())
				}
			}
		})
	}
}

func TestConnectStatusAndResponseDeadline(t *testing.T) {
	for _, status := range []int{0, 403, 404, 407, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status == 0 {
					<-r.Context().Done()
					return
				}
				w.WriteHeader(status)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			pool := x509.NewCertPool()
			pool.AddCert(server.Certificate())
			tc := &tls.Config{ServerName: "example.com", RootCAs: pool}
			c := newClient(t, "http2", server.Listener.Addr().String(), tc, func(cfg *ClientConfig) {
				cfg.HealthTimeout = 50 * time.Millisecond
				cfg.ConnectTimeout = 50 * time.Millisecond
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			e := c.Check(ctx)
			if e == nil {
				t.Fatal("non-200 accepted")
			}
			if status == 407 && !IsCode(e, Auth) {
				t.Fatal(e)
			}
			if status != 0 && status != 407 && !IsCode(e, Rejected) {
				t.Fatal(e)
			}
			if status == 0 && !errors.Is(e, context.DeadlineExceeded) && !IsCode(e, Closed) {
				t.Fatal("CONNECT deadline ownership", e)
			}
		})
	}
}

func TestMalformedUDPReplyIsTypedFramingFailure(t *testing.T) {
	for _, frame := range [][]byte{{0, 0, 0, 1}, {0, 0}, {0, 0, 0, 36}, {0, 0, 0, 36, 1}} {
		release := make(chan struct{})
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			if r.Host == "_udp2" {
				<-release
				_, _ = w.Write(frame)
			}
		}))
		server.EnableHTTP2 = true
		server.StartTLS()
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		c := newClient(t, "http2", server.Listener.Addr().String(), &tls.Config{ServerName: "example.com", RootCAs: pool}, nil)
		p, e := c.OpenPacket(context.Background(), netip.MustParseAddrPort("192.0.2.29:53"))
		if e != nil {
			t.Fatal(e)
		}
		close(release)
		p.SetReadDeadline(time.Now().Add(time.Second))
		_, _, e = p.ReadFrom(make([]byte, 64))
		if !IsCode(e, Framing) {
			t.Errorf("reply=%x error=%v", frame, e)
		}
		p.Close()
		c.Close()
		server.Close()
	}
}
