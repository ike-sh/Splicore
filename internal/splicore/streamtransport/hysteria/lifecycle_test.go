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

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func material(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	s := testkit.TLS(t)
	pair, e := tls.LoadX509KeyPair(s.CertificateFile, s.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(s.CACertificate))
	return &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h3"}}, &tls.Config{RootCAs: pool, ServerName: s.ServerName, NextProtos: []string{"h3"}}
}
func serve(t *testing.T, tc *tls.Config, h cfg.Hysteria, auth func(string) (string, bool), app func(*Connection) Hooks) (*Server, net.Addr) {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewServer(context.Background(), p, ServerConfig{TLS: tc, Settings: h, Authenticate: auth, Application: app})
	if e != nil {
		t.Fatal(e)
	}
	s.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := s.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return s, p.LocalAddr()
}

type countedSocket struct {
	net.PacketConn
	once sync.Once
	open *atomic.Int64
}

func (p *countedSocket) Close() error {
	var e error
	p.once.Do(func() { e = p.PacketConn.Close(); p.open.Add(-1) })
	return e
}
func socket(t *testing.T, a net.Addr, created, open *atomic.Int64) func(context.Context) (net.PacketConn, net.Addr, error) {
	return func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, e := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		if e != nil {
			return nil, nil, e
		}
		created.Add(1)
		open.Add(1)
		return &countedSocket{PacketConn: p, open: open}, a, nil
	}
}
func TestRejectedAuthChurn128AndCleanup(t *testing.T) {
	st, ct := material(t)
	var admitted atomic.Int64
	s, a := serve(t, st, cfg.Hysteria{Version: 2}, func(string) (string, bool) { return "", false }, func(c *Connection) Hooks { return Hooks{Admitted: func() { admitted.Add(1) }} })
	var created, open atomic.Int64
	for range 128 {
		m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "wrong-synthetic", Socket: socket(t, a, &created, &open), Settings: cfg.Hysteria{Version: 2}})
		if e != nil {
			t.Fatal(e)
		}
		if _, e = m.Acquire(context.Background()); !errors.Is(e, ErrAuth) {
			t.Fatal(e)
		}
		if m.ActiveConnections() != 0 || open.Load() != 0 {
			t.Fatal("failed admission retained socket or pool")
		}
		m.Close()
	}
	if created.Load() != 128 || admitted.Load() != 0 {
		t.Fatal("churn count/admission")
	}
	if e := s.Close(context.Background()); e != nil || s.ActiveConnections() != 0 {
		t.Fatal("server cleanup", e)
	}
}
func TestCancelDuringAuth128AndTLSFailure(t *testing.T) {
	st, ct := material(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{}, 1)
	s, a := serve(t, st, cfg.Hysteria{Version: 2}, func(string) (string, bool) { entered <- struct{}{}; <-release; return "A", true }, func(*Connection) Hooks { return Hooks{} })
	var created, open atomic.Int64
	for range 128 {
		m, _ := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "synthetic", Socket: socket(t, a, &created, &open), Settings: cfg.Hysteria{Version: 2}})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, e := m.Acquire(ctx); done <- e }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("auth did not start")
		}
		cancel()
		release <- struct{}{}
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancel stalled")
		}
		m.Close()
		if open.Load() != 0 || m.ActiveConnections() != 0 {
			t.Fatal("canceled auth retained resources")
		}
	}
	bad := ct.Clone()
	bad.ServerName = "wrong.synthetic.test"
	m, _ := NewManager(context.Background(), ClientConfig{TLS: bad, Password: "synthetic", Socket: socket(t, a, &created, &open), Settings: cfg.Hysteria{Version: 2}})
	if _, e := m.Acquire(context.Background()); e == nil {
		t.Fatal("bad certificate accepted")
	}
	m.Close()
	if open.Load() != 0 {
		t.Fatal("TLS failure leaked socket")
	}
	s.Close(context.Background())
}
func TestPoolReuseConcurrentReconnectAndOwnerKeepAlive(t *testing.T) {
	st, ct := material(t)
	connections := make(chan *Connection, 8)
	_, a := serve(t, st, cfg.Hysteria{Version: 2}, func(p string) (string, bool) { return p, p == "A" || p == "B" }, func(c *Connection) Hooks { connections <- c; return Hooks{} })
	var created, open atomic.Int64
	config := ClientConfig{TLS: ct, Password: "A", Socket: socket(t, a, &created, &open), Settings: cfg.Hysteria{Version: 2, QUIC: cfg.QUIC{KeepAlivePeriod: 1}}}
	m, _ := NewManager(context.Background(), config)
	defer m.Close()
	results := make(chan *Connection, 32)
	errs := make(chan error, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			c, e := m.Acquire(context.Background())
			if e != nil {
				errs <- e
			}
			results <- c
		})
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	var first *Connection
	for c := range results {
		if first == nil {
			first = c
		}
		if c != first {
			t.Fatal("duplicate pool connection")
		}
	}
	serverA := <-connections
	if serverA.Identity() != "A" || created.Load() != 1 {
		t.Fatal("pool identity")
	}
	config.Password = "B"
	config.TLS = ct.Clone()
	config.Settings.QUIC.MaxIdleTimeout = 4
	b, _ := NewManager(context.Background(), config)
	other, e := b.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	serverB := <-connections
	if other == first || serverB.Identity() != "B" {
		t.Fatal("credential bleed")
	}
	b.Close()
	_ = first.QUIC.CloseWithError(0, "")
	<-first.Context().Done()
	next, e := m.Acquire(context.Background())
	if e != nil || next == first {
		t.Fatal("stale pooled connection", e)
	}
	m.Close()
	if open.Load() != 0 || m.ActiveConnections() != 0 {
		t.Fatal("keepalive owner leaked")
	}
	if _, e = m.Acquire(context.Background()); !errors.Is(e, net.ErrClosed) {
		t.Fatal("post-close dial", e)
	}
}
func raw(t *testing.T, tc *tls.Config, a net.Addr) (*quic.Conn, *http3.ClientConn) {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	tr := &quic.Transport{Conn: p}
	q, e := tr.Dial(context.Background(), a, tc, carrier(cfg.QUIC{}))
	if e != nil {
		tr.Close()
		p.Close()
		t.Fatal(e)
	}
	h := &http3.Transport{}
	client := h.NewClientConn(q)
	t.Cleanup(func() { q.CloseWithError(0, ""); h.Close(); tr.Close(); p.Close() })
	return q, client
}
func request(t *testing.T, h *http3.ClientConn, path, auth string) (int, string, http.Header) {
	t.Helper()
	u, _ := url.Parse("https://hysteria" + path)
	r := &http.Request{Method: "POST", URL: u, Header: http.Header{"Hysteria-Auth": []string{auth}, "Hysteria-Cc-Rx": []string{"0"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, e := h.RoundTrip(r.WithContext(ctx))
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if e != nil {
		t.Fatal(e)
	}
	return resp.StatusCode, string(b), resp.Header
}
func TestRepeatAuthImmutableAndUnauthenticatedSurface(t *testing.T) {
	st, ct := material(t)
	admitted := make(chan *Connection, 2)
	_, a := serve(t, st, cfg.Hysteria{Version: 2}, func(p string) (string, bool) { return p, p == "A" || p == "B" }, func(c *Connection) Hooks { return Hooks{Admitted: func() { admitted <- c }} })
	q, h := raw(t, ct, a)
	if status, _, _ := request(t, h, "/ordinary", "A"); status != 404 {
		t.Fatal("non-auth admitted")
	}
	if e := q.SendDatagram([]byte("preauth")); e != nil {
		t.Fatal(e)
	}
	if status, _, header := request(t, h, "/auth", "A"); status != 233 || header.Get("Hysteria-UDP") != "true" {
		t.Fatal("auth response")
	}
	c := <-admitted
	if status, _, _ := request(t, h, "/auth", "B"); status != 404 || c.Identity() != "A" {
		t.Fatal("repeat credential switched")
	}
	if status, _, _ := request(t, h, "/auth", "A"); status != 233 {
		t.Fatal("idempotent auth")
	}
	select {
	case <-admitted:
		t.Fatal("duplicate admission")
	default:
	}
}
func TestPreauthCarrierAndDisabledUDP(t *testing.T) {
	st, ct := material(t)
	accepted := make(chan *Connection, 2)
	var dispatched atomic.Int64
	_, a := serve(t, st, cfg.Hysteria{Version: 2, DisableUDP: true}, func(string) (string, bool) { return "A", true }, func(c *Connection) Hooks {
		accepted <- c
		return Hooks{Dispatch: func(http3.FrameType, *quic.Stream, error) (bool, error) { dispatched.Add(1); return false, nil }}
	})
	q, h := raw(t, ct, a)
	server := <-accepted
	if e := q.SendDatagram([]byte("preauth")); e != nil {
		t.Fatal(e)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for server.discarded.Load() == 0 {
		select {
		case <-deadline.C:
			t.Fatal("preauth datagram not consumed")
		case <-tick.C:
		}
	}
	if status, _, header := request(t, h, "/auth", "A"); status != 233 || header.Get("Hysteria-UDP") != "false" {
		t.Fatal("disabled capability advertised")
	}
	if len(server.datagrams) != 0 {
		t.Fatal("preauth datagram retained")
	}
	q2, _ := raw(t, ct, a)
	<-accepted
	stream, e := q2.OpenStreamSync(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = stream.Write([]byte{0x44, 0x01, 1, 'x', 0})
	if _, e = stream.Read(make([]byte, 1)); e == nil || dispatched.Load() != 0 {
		t.Fatal("preauth stream admitted")
	}
}
func TestCCRXWireUnitsAndMalformedResponse(t *testing.T) {
	for _, s := range []string{"0", "1", "125000", "2500000", "18446744073709551615"} {
		if _, auto, e := CCRX(s, false); e != nil || auto {
			t.Fatal(s, e)
		}
	}
	if n, auto, e := CCRX("auto", true); n != 0 || !auto || e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"", "-1", "+1", "1 mbps", "18446744073709551616", "auto", " 0", "0\n"} {
		if _, _, e := CCRX(s, false); e == nil {
			t.Fatal("invalid wire rate", s)
		}
	}
}
func TestProxyHandlerShutdownWaitsForCancellation(t *testing.T) {
	st, ct := material(t)
	entered, exited := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done(); close(exited) }))
	defer upstream.Close()
	s, a := serve(t, st, cfg.Hysteria{Version: 2, Masquerade: &cfg.Masquerade{Type: "proxy", URL: upstream.URL}}, func(string) (string, bool) { return "", false }, func(*Connection) Hooks { return Hooks{} })
	_, h := raw(t, ct, a)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		u, _ := url.Parse("https://hysteria/ordinary")
		r := &http.Request{Method: "GET", URL: u, Header: make(http.Header)}
		resp, _ := h.RoundTrip(r)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := s.Close(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case <-exited:
	case <-ctx.Done():
		t.Fatal("upstream cancellation not propagated")
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("H3 request survived owner")
	}
}
func TestMasqueradeModesAndInitializationRollback(t *testing.T) {
	st, ct := material(t)
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "public.txt"), []byte("file-content"), 0600)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Hysteria-Auth") != "" {
			t.Error("auth credential forwarded")
		}
		w.Header().Set("X-Controlled", "yes")
		io.WriteString(w, "proxy-content")
	}))
	defer upstream.Close()
	for _, m := range []cfg.Masquerade{{Type: "404"}, {Type: "string", Content: "string-content", Status: 403, Headers: map[string]string{"X-Test": "yes"}}, {Type: "file", Directory: root}, {Type: "proxy", URL: upstream.URL, RewriteHost: true}} {
		t.Run(m.Type, func(t *testing.T) {
			s, a := serve(t, st, cfg.Hysteria{Version: 2, Masquerade: &m}, func(string) (string, bool) { return "", false }, func(*Connection) Hooks { return Hooks{} })
			_, h := raw(t, ct, a)
			path := "/auth"
			if m.Type == "file" {
				path = "/public.txt"
			}
			status, body, header := request(t, h, path, "invalid")
			switch m.Type {
			case "404":
				if status != 404 {
					t.Fatal(status)
				}
			case "string":
				if status != 403 || body != "string-content" || header.Get("X-Test") != "yes" {
					t.Fatal(status, body)
				}
			case "file":
				if status != 200 || body != "file-content" {
					t.Fatal(status, body)
				}
			case "proxy":
				if status != 200 || body != "proxy-content" || header.Get("X-Controlled") != "yes" {
					t.Fatal(status, body)
				}
			}
			s.Close(context.Background())
		})
	}
	for _, c := range []ServerConfig{{}, {TLS: st, Settings: cfg.Hysteria{Version: 2}}, {TLS: st, Settings: cfg.Hysteria{Version: 1}, Authenticate: func(string) (string, bool) { return "", false }, Application: func(*Connection) Hooks { return Hooks{} }}} {
		p, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		if _, e := NewServer(context.Background(), p, c); e == nil {
			t.Fatal("invalid initialized")
		}
		if _, e := p.WriteTo([]byte{1}, p.LocalAddr()); !errors.Is(e, net.ErrClosed) {
			t.Fatal("rollback leaked socket", e)
		}
	}
	// File-open failure occurs after valid TLS/validator/settings and an owned
	// UDP bind, exercising a later startup rollback without a new bind attempt.
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = NewServer(context.Background(), p, ServerConfig{TLS: st, Settings: cfg.Hysteria{Version: 2, Masquerade: &cfg.Masquerade{Type: "file", Directory: filepath.Join(root, "absent")}}, Authenticate: func(string) (string, bool) { return "A", true }, Application: func(*Connection) Hooks { return Hooks{} }}); e == nil {
		t.Fatal("missing file root initialized")
	}
	if _, e = p.WriteTo([]byte{1}, p.LocalAddr()); !errors.Is(e, net.ErrClosed) {
		t.Fatal("late startup rollback retained socket", e)
	}
}
