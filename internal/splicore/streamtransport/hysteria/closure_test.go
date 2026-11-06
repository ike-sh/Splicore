package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go/http3"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type observedSocket struct {
	net.PacketConn
	closed     atomic.Bool
	afterClose atomic.Int64
	writes     chan time.Time
	drop       atomic.Bool
}

func (p *observedSocket) WriteTo(b []byte, a net.Addr) (int, error) {
	if p.closed.Load() {
		p.afterClose.Add(1)
	}
	select {
	case p.writes <- time.Now():
	default:
	}
	if p.drop.Load() {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, a)
}
func (p *observedSocket) Close() error { p.closed.Store(true); return p.PacketConn.Close() }
func (p *observedSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := p.PacketConn.ReadFrom(b)
		if e != nil || !p.drop.Load() {
			return n, a, e
		}
	}
}

func TestKeepAlivePacketsStopAndDeadPeerIdleReleases(t *testing.T) {
	st, ct := material(t)
	for _, idle := range []bool{false, true} {
		t.Run(map[bool]string{false: "keepalive", true: "idle"}[idle], func(t *testing.T) {
			_, a := serve(t, st, cfg.Hysteria{Version: 2, QUIC: cfg.QUIC{MaxIdleTimeout: 4}}, func(string) (string, bool) { return "A", true }, func(*Connection) Hooks { return Hooks{} })
			p, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			observed := &observedSocket{PacketConn: p, writes: make(chan time.Time, 128)}
			q := cfg.QUIC{MaxIdleTimeout: 4}
			if !idle {
				q.KeepAlivePeriod = 1
			}
			m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2, QUIC: q}, Socket: func(context.Context) (net.PacketConn, net.Addr, error) { return observed, a, nil }})
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			c, e := m.Acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if idle {
				observed.drop.Store(true)
				select {
				case <-c.Context().Done():
				case <-time.After(7 * time.Second):
					t.Fatal("dead peer did not expire")
				}
				m.Close()
				if !observed.closed.Load() || m.ActiveConnections() != 0 {
					t.Fatal("idle retained owner")
				}
			} else {
				// After admission, no streams/datagrams are opened. Observe two actual
				// sends beyond the handshake tail, separated by the configured period.
				start := time.Now()
				seen := 0
				deadline := time.NewTimer(4 * time.Second)
				defer deadline.Stop()
				for seen < 2 {
					select {
					case when := <-observed.writes:
						if when.Sub(start) >= time.Duration(seen+1)*800*time.Millisecond {
							seen++
						}
					case <-deadline.C:
						t.Fatal("keepalive packets absent")
					}
				}
				m.Close()
				before := observed.afterClose.Load()
				timer := time.NewTimer(2200 * time.Millisecond)
				<-timer.C
				if observed.afterClose.Load() != before || before != 0 || !observed.closed.Load() || m.ActiveConnections() != 0 {
					t.Fatal("packets after owner close")
				}
			}
		})
	}
}

func TestMalformedH3FailureTransactionsAndTLSModes(t *testing.T) {
	st, ct := material(t)
	for _, row := range []struct {
		name, rx, udp string
		status        int
	}{{"non233", "auto", "true", 403}, {"bad-rx", "1 mbps", "true", 233}, {"bad-udp", "auto", "yes", 233}} {
		t.Run(row.name, func(t *testing.T) {
			p, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			h := &http3.Server{TLSConfig: st, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Hysteria-CC-RX", row.rx)
				w.Header().Set("Hysteria-UDP", row.udp)
				w.WriteHeader(row.status)
			})}
			done := make(chan struct{})
			go func() { defer close(done); h.Serve(p) }()
			defer func() { h.Close(); p.Close(); <-done }()
			var created, open atomic.Int64
			for range 128 {
				m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2}, Socket: socket(t, p.LocalAddr(), &created, &open)})
				if e != nil {
					t.Fatal(e)
				}
				if _, e = m.Acquire(context.Background()); !errors.Is(e, ErrAuth) {
					t.Fatal("malformed admitted", e)
				}
				m.Close()
				if open.Load() != 0 || m.ActiveConnections() != 0 {
					t.Fatal("failed auth retained resources")
				}
			}
			if created.Load() != 128 {
				t.Fatal("churn population")
			}
		})
	}
	_, a := serve(t, st, cfg.Hysteria{Version: 2}, func(string) (string, bool) { return "A", true }, func(*Connection) Hooks { return Hooks{} })
	for _, mode := range []string{"verified", "wrong-ca", "insecure"} {
		t.Run(mode, func(t *testing.T) {
			c := ct.Clone()
			if mode == "wrong-ca" {
				c.RootCAs = x509.NewCertPool()
			}
			if mode == "insecure" {
				c.RootCAs = x509.NewCertPool()
				c.InsecureSkipVerify = true
			}
			var created, open atomic.Int64
			m, e := NewManager(context.Background(), ClientConfig{TLS: c, Password: "A", Settings: cfg.Hysteria{Version: 2}, Socket: socket(t, a, &created, &open)})
			if e != nil {
				t.Fatal(e)
			}
			_, e = m.Acquire(context.Background())
			if (e == nil) != (mode != "wrong-ca") {
				t.Fatal(mode, e)
			}
			m.Close()
			if open.Load() != 0 {
				t.Fatal("TLS retained socket")
			}
		})
	}
	for _, failure := range []string{"socket-error", "nil-peer", "closed-socket"} {
		t.Run(failure, func(t *testing.T) {
			var created, open atomic.Int64
			sf := socket(t, a, &created, &open)
			m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2}, Socket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				if failure == "socket-error" {
					return nil, nil, net.ErrClosed
				}
				p, a, e := sf(ctx)
				if failure == "nil-peer" {
					return p, nil, e
				}
				p.Close()
				return p, a, e
			}})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = m.Acquire(context.Background()); e == nil {
				t.Fatal("failed stage accepted")
			}
			m.Close()
			if open.Load() != 0 || m.ActiveConnections() != 0 {
				t.Fatal("rollback")
			}
		})
	}
}

func TestRootFileTraversalAndHTTPHTTPSProxyBoundaries(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		root := t.TempDir()
		outside := t.TempDir()
		os.WriteFile(filepath.Join(outside, "secret"), []byte("outside-secret"), 0600)
		os.WriteFile(filepath.Join(root, "visible"), []byte("visible"), 0600)
		if e := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "escape")); e != nil {
			t.Fatal(e)
		}
		h, closeRoot, e := masquerade(&cfg.Masquerade{Type: "file", Directory: root}, nil)
		if e != nil {
			t.Fatal(e)
		}
		for _, path := range []string{"/escape", "/../secret", "/%2e%2e/secret"} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "https://ordinary"+path, nil))
			if w.Body.String() == "outside-secret" || w.Code == 200 {
				t.Fatal("root escaped", path, w.Code)
			}
		}
		closeRoot()
	})
	t.Run("proxy", func(t *testing.T) {
		for _, secure := range []bool{false, true} {
			for _, rewrite := range []bool{false, true} {
				name := "http"
				if secure {
					name = "https"
				}
				if rewrite {
					name += "-rewrite"
				}
				t.Run(name, func(t *testing.T) {
					var upstreamHost string
					var calls atomic.Int64
					var mu sync.Mutex
					up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						upstreamHost = r.Host
						mu.Unlock()
						calls.Add(1)
						if r.Header.Get("Hysteria-Auth") != "" {
							t.Error("auth leaked")
						}
						w.Header().Set("Hysteria-UDP", "true")
						w.Header().Set("Hysteria-CC-RX", "auto")
						w.WriteHeader(233)
						io.WriteString(w, "upstream-body")
					}))
					if secure {
						up.StartTLS()
					} else {
						up.Start()
					}
					defer up.Close()
					h, cleanup, e := masquerade(&cfg.Masquerade{Type: "proxy", URL: up.URL, RewriteHost: rewrite, Insecure: secure}, (&net.Dialer{}).DialContext)
					if e != nil {
						t.Fatal(e)
					}
					r := httptest.NewRequest("POST", "https://original.example/auth", nil)
					r.Header.Set("Hysteria-Auth", "invalid")
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 502 || w.Body.String() != "upstream-body" || w.Header().Get("Hysteria-UDP") != "" {
						t.Fatal("proxy forged admission", w.Code, w.Header())
					}
					mu.Lock()
					host := upstreamHost
					mu.Unlock()
					want := "original.example"
					if rewrite {
						u, _ := url.Parse(up.URL)
						want = u.Host
					}
					if host != want || calls.Load() != 1 {
						t.Fatal("Host", host, want)
					}
					cleanup()
					up.Close()
					w = httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != 502 {
						t.Fatal("upstream error", w.Code)
					}
					cleanup()
				})
			}
		}
	})
}

func TestServerCloseDuringAuthAndTLSQUICIdentityIsolation(t *testing.T) {
	st, ct := material(t)
	entered, release := make(chan struct{}), make(chan struct{})
	accepted := make(chan *Connection, 1)
	s, a := serve(t, st, cfg.Hysteria{Version: 2}, func(string) (string, bool) { close(entered); <-release; return "A", true }, func(c *Connection) Hooks { accepted <- c; return Hooks{} })
	var created, open atomic.Int64
	m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2}, Socket: socket(t, a, &created, &open)})
	if e != nil {
		t.Fatal(e)
	}
	dialed := make(chan error, 1)
	go func() { _, e := m.Acquire(context.Background()); dialed <- e }()
	<-entered
	c := <-accepted
	closed := make(chan error, 1)
	go func() { closed <- s.Close(context.Background()) }()
	select {
	case <-c.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("owner did not cancel auth")
	}
	close(release)
	if e = <-dialed; e == nil {
		t.Fatal("auth accepted after server close")
	}
	if e = <-closed; e != nil {
		t.Fatal(e)
	}
	m.Close()
	if open.Load() != 0 || m.ActiveConnections() != 0 || s.ActiveConnections() != 0 {
		t.Fatal("server-close auth rollback")
	}
	_, a = serve(t, st, cfg.Hysteria{Version: 2}, func(p string) (string, bool) { return p, true }, func(*Connection) Hooks { return Hooks{} })
	var all []*Manager
	var conns []*Connection
	for _, row := range []struct {
		tls *tls.Config
		q   cfg.QUIC
	}{{ct, cfg.QUIC{}}, {ct, cfg.QUIC{Congestion: "bbr", MaxIdleTimeout: 4}}, {&tls.Config{ServerName: "explicit-insecure.example", InsecureSkipVerify: true}, cfg.QUIC{KeepAlivePeriod: 1}}} {
		m, e := NewManager(context.Background(), ClientConfig{TLS: row.tls, Password: "A", Settings: cfg.Hysteria{Version: 2, QUIC: row.q}, Socket: socket(t, a, &created, &open)})
		if e != nil {
			t.Fatal(e)
		}
		c, e := m.Acquire(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		all = append(all, m)
		conns = append(conns, c)
	}
	for i, c := range conns {
		for j, d := range conns {
			if i != j && c == d {
				t.Fatal("TLS/QUIC identity shared")
			}
		}
	}
	for _, m := range all {
		m.Close()
	}
	if open.Load() != 0 {
		t.Fatal("identity owner baseline")
	}
}

func TestManagerOwnsTrustPoolSnapshot(t *testing.T) {
	st, ct := material(t)
	_, a := serve(t, st, cfg.Hysteria{Version: 2}, func(string) (string, bool) { return "A", true }, func(*Connection) Hooks { return Hooks{} })
	ct.RootCAs = x509.NewCertPool()
	var created, open atomic.Int64
	m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2}, Socket: socket(t, a, &created, &open)})
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	leaf, e := x509.ParseCertificate(st.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	ct.RootCAs.AddCert(leaf)
	if len(m.config.TLS.RootCAs.Subjects()) != 0 {
		t.Fatal("caller modified owner trust identity")
	}
	if _, e = m.Acquire(context.Background()); e == nil {
		t.Fatal("mutated caller trust authorized peer")
	}
	m.Close()
	if open.Load() != 0 {
		t.Fatal("trust failure retained socket")
	}
}
