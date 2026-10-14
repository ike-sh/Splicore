package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func eventually(t *testing.T, check func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if check() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("lifecycle worker did not finish")
}

func TestNaiveRegularH2ClientUsesUnpaddedTunnel(t *testing.T) {
	proxy, tc, _ := startTestServer(t, "https")
	target := echoTarget(t, "tcp", "127.0.0.1:0")
	transport := &http2.Transport{TLSClientConfig: tc, DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, _ string, config *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{NetDialer: &net.Dialer{}, Config: config}).DialContext(ctx, network, proxy)
		}}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: http.Header{"Proxy-Authorization": {Authorization("alpha", "alpha-pass")}}, Body: reader, ContentLength: -1}
	response, err := transport.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.Header.Values("Padding")) != 0 {
		t.Fatal("ordinary client negotiated padding")
	}
	data := bytes.Repeat([]byte{0x51}, 65536)
	sent := make(chan error, 1)
	go func() { _, err := writer.Write(data); writer.Close(); sent <- err }()
	got, err := io.ReadAll(response.Body)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("raw tunnel payload", len(got), err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}
func TestNaivePoolCapacityRetirementIdleAndReconnect(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, server := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			var count atomic.Int64
			client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) {
				c.MaxStreams = 2
				c.IdleTimeout = 2 * time.Second
				c.TunnelTimeout = 150 * time.Millisecond
			}, &count)
			ctx := context.Background()
			first, err := client.Open(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := client.Open(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			if conn, err := client.Open(ctx, target); !errors.Is(err, ErrBusy) {
				if conn != nil {
					conn.Close()
				}
				t.Fatal("capacity", err)
			}
			// Keep the old stream active across retirement. It must keep carrying
			// data while new CONNECTs use a new underlying connection.
			for range 8 {
				_ = first.SetDeadline(time.Now().Add(time.Second))
				if _, err := first.Write([]byte{9}); err != nil {
					t.Fatal(err)
				}
				var got [1]byte
				if _, err := io.ReadFull(first, got[:]); err != nil || got[0] != 9 {
					t.Fatal(err)
				}
				time.Sleep(30 * time.Millisecond)
			}
			second.Close()
			third, err := client.Open(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			defer third.Close()
			if count.Load() != 2 {
				t.Fatal("new connection after retirement", count.Load())
			}
			// A dead connection cannot be returned from the pool.
			client.mu.Lock()
			var slot *poolSlot
			for _, candidate := range client.slots {
				if candidate != nil {
					slot = candidate
					break
				}
			}
			client.mu.Unlock()
			if slot == nil {
				t.Fatal("missing live connection")
			}
			_ = slot.conn.close()
			third.Close()
			transfer(t, client, target, 65536)
			if count.Load() != 3 {
				t.Fatal("dead connection was reused")
			}
			eventually(t, func() bool { client.mu.Lock(); defer client.mu.Unlock(); return len(client.retired) == 0 })
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if conn, err := client.Open(ctx, target); err == nil {
				conn.Close()
				t.Fatal("closed client admitted")
			}
			client.mu.Lock()
			active := len(client.capacity) + len(client.retired)
			client.mu.Unlock()
			if active != 0 {
				t.Fatal("stream ownership leak", active)
			}
			closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if err := server.Close(closeCtx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNaiveCancellationDialFailureTLSAndShutdown(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, server := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			client := newTestClient(t, mode, proxy, tc, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if conn, err := client.Open(ctx, target); err == nil {
				conn.Close()
				t.Fatal("canceled dial accepted")
			}
			if conn, err := client.Open(context.Background(), "127.0.0.1:1"); err == nil {
				conn.Close()
				t.Fatal("destination failure accepted")
			}
			bad := tc.Clone()
			bad.ServerName = "wrong.synthetic.test"
			untrusted := newTestClient(t, mode, proxy, bad, nil, nil)
			if conn, err := untrusted.Open(context.Background(), target); err == nil {
				conn.Close()
				t.Fatal("wrong certificate accepted")
			}
			conn, err := client.Open(context.Background(), target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			closed := make(chan error, 1)
			go func() { var b [1]byte; _, err := conn.Read(b[:]); closed <- err }()
			closeCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := server.Close(closeCtx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-closed:
				if err == nil {
					t.Fatal("shutdown read succeeded")
				}
			case <-closeCtx.Done():
				t.Fatal("shutdown stuck stream")
			}
		})
	}
}

func TestNaiveRegularH2ProxyPaddingFallback(t *testing.T) {
	var offered atomic.Bool
	regular := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.Header.Get("Proxy-Authorization") != Authorization("alpha", "alpha-pass") {
			http.Error(w, "invalid", 400)
			return
		}
		offered.Store(r.Header.Get("Padding") != "")
		conn, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "target", 502)
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(r.Context(), func() { conn.Close() })
		defer stop()
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		done := make(chan struct{})
		go func() { _, _ = io.Copy(conn, r.Body); _ = conn.(*net.TCPConn).CloseWrite(); close(done) }()
		_, _ = io.Copy(flushWriter{w}, conn)
		conn.Close()
		<-done
	}))
	regular.EnableHTTP2 = true
	regular.StartTLS()
	defer regular.Close()
	u, _ := url.Parse(regular.URL)
	tc := regular.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tc.InsecureSkipVerify = false
	tc.ServerName = "example.com"
	client := newTestClient(t, "https", u.Host, tc, nil, nil)
	target := echoTarget(t, "tcp", "127.0.0.1:0")
	transfer(t, client, target, 65536)
	if !offered.Load() {
		t.Fatal("negotiation was not offered")
	}
	strict := newTestClient(t, "https", u.Host, tc, func(c *ClientConfig) { c.Padding = "enabled" }, nil)
	if conn, err := strict.Open(context.Background(), target); err == nil {
		conn.Close()
		t.Fatal("required padding ignored")
	}
}

func TestNaiveRequestRobustnessAndPaddingHeader(t *testing.T) {
	_, _, s := startTestServer(t, "https")
	for _, row := range []struct {
		name, method, target string
		headers              http.Header
		code                 int
	}{
		{"missing-port", "CONNECT", "localhost", nil, 400}, {"invalid-port", "CONNECT", "localhost:0", nil, 400},
		{"malformed-ipv6", "CONNECT", "[::1:443", nil, 400}, {"empty", "CONNECT", "", nil, 400},
		{"missing-auth", "CONNECT", "localhost:443", nil, 407},
		{"invalid-basic", "CONNECT", "localhost:443", http.Header{"Proxy-Authorization": {"Basic !!!"}}, 407},
		{"duplicate-auth", "CONNECT", "localhost:443", http.Header{"Proxy-Authorization": {"a", "b"}}, 400},
		{"ambiguous-padding", "CONNECT", "localhost:443", http.Header{"Padding": {"a", "b"}}, 400},
		{"wrong-auth", "CONNECT", "localhost:443", http.Header{"Proxy-Authorization": {Authorization("alpha", "beta-pass")}}, 407},
		{"method", "POST", "localhost:443", nil, 405},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := &http.Request{Method: row.method, Host: row.target, URL: &url.URL{Host: row.target}, Header: row.headers, ProtoMajor: 2}
			w := &recordingWriter{header: http.Header{}}
			s.ServeHTTP(w, r)
			if w.code != row.code || bytes.Contains(w.body.Bytes(), []byte("beta-pass")) {
				t.Fatal(w.code, w.body.String())
			}
		})
	}
	for _, response := range []bool{false, true} {
		for range 64 {
			p, err := HeaderPadding(response)
			low, high := 16, 32
			if response {
				low, high = 30, 62
			}
			if err != nil || len(p) < low || len(p) > high {
				t.Fatal("header range", err)
			}
		}
	}
	if yes, err := paddingOffered(http.Header{"Padding": {""}}); !yes || err != nil {
		t.Fatal("presence, not value, required")
	}
}

func TestNaiveCancelDuringCONNECTJoinsDestinationDial(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			entered, finished := make(chan struct{}), make(chan struct{})
			proxy, tc, _ := startTestServerConfigured(t, mode, func(c *ServerConfig) {
				original := c.Dial
				c.Dial = func(ctx context.Context, user, target string) (net.Conn, error) {
					if target != "127.0.0.1:65534" {
						return original(ctx, user, target)
					}
					close(entered)
					defer close(finished)
					<-ctx.Done()
					return nil, ctx.Err()
				}
			})
			client := newTestClient(t, mode, proxy, tc, nil, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				conn, err := client.Open(ctx, "127.0.0.1:65534")
				if conn != nil {
					conn.Close()
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("CONNECT never dialed")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled CONNECT succeeded")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("stuck CONNECT")
			}
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("destination dial leak")
			}
			transfer(t, client, echoTarget(t, "tcp", "127.0.0.1:0"), 65536)
		})
	}
}
