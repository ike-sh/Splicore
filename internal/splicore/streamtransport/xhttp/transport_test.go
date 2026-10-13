package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func tlsPair(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	m := testkit.TLSForName(t, "xhttp.synthetic.test")
	a, _ := os.ReadFile(m.CertificateFile)
	b, _ := os.ReadFile(m.PrivateKeyFile)
	p, e := tls.X509KeyPair(a, b)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(m.CACertificate))
	return &tls.Config{Certificates: []tls.Certificate{p}, MinVersion: tls.VersionTLS13}, &tls.Config{ServerName: m.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS13}
}
func fixture(t *testing.T, c cfg.Config, version int) (*Client, *Listener) {
	t.Helper()
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var server, client *tls.Config
	if version > 0 {
		server, client = tlsPair(t)
		if version == 1 {
			client.NextProtos = []string{"http/1.1"}
			server.NextProtos = client.NextProtos
		}
	}
	sc := c.Clone()
	if sc.XHTTP != nil {
		sc.XHTTP.XMUX = nil
		sc.XHTTP.Download = nil
		sc.XHTTP.Interval = cfg.Range{}
		sc.XHTTP.Chunk = cfg.Range{}
		sc.XHTTP.NoGRPC = false
		sc.XHTTP.SessionTable = ""
		sc.XHTTP.SessionLength = cfg.Range{}
	}
	ln, e := NewListener(raw, sc, server, nil)
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	l := ln.(*Listener)
	cl, e := NewClient((&net.Dialer{}).DialContext, l.Addr().String(), c, Security{TLS: client}, nil)
	if e != nil {
		l.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { cl.Close(); l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return cl, l
}
func exchange(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	sent := make(chan error, 1)
	go func() { _, e := c.Write(payload); sent <- e }()
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatal("reply", len(payload), e)
	}
	if e := <-sent; e != nil || !bytes.Equal(got, payload) {
		t.Fatal("integrity", e)
	}
	_ = c.SetDeadline(time.Time{})
}
func TestXHTTPModesPayloadLifecycle(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		for _, h := range []int{0, 1, 2} {
			if mode == "stream-one" && h < 2 {
				continue
			}
			t.Run(mode+"/H"+strconv.Itoa(h), func(t *testing.T) {
				cl, l := fixture(t, cfg.Config{Kind: "xhttp", Path: "/core?fixed=1", Host: "authority.synthetic.test", XHTTP: &cfg.XHTTP{Mode: mode}}, h)
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				for _, size := range []int{1, 53, 32768, 65537, 3 << 20} {
					t.Run("bytes-"+strconv.Itoa(size), func(t *testing.T) { exchange(t, c, bytes.Repeat([]byte{byte(size % 253)}, size)) })
				}
				t.Run("tiny-writes", func(t *testing.T) {
					done := make(chan error, 1)
					go func() {
						for i := 0; i < 500; i++ {
							if _, e := c.Write([]byte{byte(i)}); e != nil {
								done <- e
								return
							}
						}
						done <- nil
					}()
					got := make([]byte, 500)
					c.SetDeadline(time.Now().Add(10 * time.Second))
					if _, e := io.ReadFull(c, got); e != nil {
						t.Fatal(e)
					}
					if e := <-done; e != nil {
						t.Fatal(e)
					}
					for i, b := range got {
						if b != byte(i) {
							t.Fatal("tiny write ordering")
						}
					}
				})
				c.Close()
				cl.Close()
				l.Close()
				l.mu.Lock()
				defer l.mu.Unlock()
				if len(l.sessions) != 0 || l.pending != 0 {
					t.Fatal("session or bytes leaked")
				}
			})
		}
	}
}
func TestXHTTPPlacementsPaddingMethods(t *testing.T) {
	for _, s := range []string{"path", "header", "query", "cookie"} {
		for _, seq := range []string{"path", "header", "query", "cookie"} {
			t.Run(s+"/"+seq, func(t *testing.T) {
				cl, _ := fixture(t, cfg.Config{Kind: "xhttp", Path: "/placements", XHTTP: &cfg.XHTTP{Mode: "packet-up", SessionPlacement: s, SequencePlacement: seq}}, 2)
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				exchange(t, c, []byte("session/sequence placement"))
			})
		}
	}
	for _, p := range []string{"body", "auto", "header", "cookie"} {
		for _, m := range []string{"POST", "GET", "PUT", "PATCH", "DELETE"} {
			t.Run(p+"/"+m, func(t *testing.T) {
				cl, _ := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up", DataPlacement: p, Method: m}}, 2)
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				exchange(t, c, bytes.Repeat([]byte{59}, 17000))
			})
		}
	}
	for _, p := range []string{"header", "queryInHeader", "query", "cookie"} {
		for _, method := range []string{"repeat-x", "tokenish"} {
			t.Run(p+"/"+method, func(t *testing.T) {
				cl, _ := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{PaddingObfs: true, PaddingPlacement: p, PaddingMethod: method, Padding: cfg.Range{64, 64}}}, 2)
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				exchange(t, c, []byte("padding envelope"))
			})
		}
	}
}
func TestXHTTPConcurrentIsolationReuseAndDeadlines(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			cl, l := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: mode, XMUX: &cfg.XMUX{MaxConnections: cfg.Range{1, 1}}}}, 2)
			var wg sync.WaitGroup
			conns := make([]net.Conn, 8)
			for i := range conns {
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				conns[i] = c
				defer c.Close()
			}
			conns[0].Close()
			for i := 1; i < len(conns); i++ {
				wg.Add(1)
				go func(i int) { defer wg.Done(); exchange(t, conns[i], bytes.Repeat([]byte{byte(i)}, 65537)) }(i)
			}
			wg.Wait()
			l.mu.Lock()
			sockets := len(l.connections)
			l.mu.Unlock()
			if sockets != 1 {
				t.Fatal("H2 connection reuse", sockets)
			}
			c := conns[1]
			errch := make(chan error, 1)
			go func() { _, e := c.Read(make([]byte, 1)); errch <- e }()
			c.SetReadDeadline(time.Now().Add(-time.Second))
			if e := <-errch; !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal("read deadline", e)
			}
			c.SetReadDeadline(time.Time{})
			exchange(t, c, []byte("deadline recovery"))
			c.Close()
			cl.Close()
			l.Close()
		})
	}
}

func TestXHTTPH1ConcurrentDownloadsLeaveUploadCapacity(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "auto"} {
		t.Run(mode, func(t *testing.T) {
			cl, _ := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: mode, XMUX: &cfg.XMUX{MaxConnections: cfg.Range{1, 1}}}}, 1)
			conns := make([]net.Conn, 8)
			for i := range conns {
				c, e := cl.DialContext(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				conns[i] = c
				defer c.Close()
			}
			conns[0].Close()
			var wg sync.WaitGroup
			for i := 1; i < len(conns); i++ {
				wg.Add(1)
				go func(i int) { defer wg.Done(); exchange(t, conns[i], bytes.Repeat([]byte{byte(i)}, 65537)) }(i)
			}
			wg.Wait()
		})
	}
}

func TestXHTTPStreamingHeadersAndKeepalive(t *testing.T) {
	for _, noSSE := range []bool{false, true} {
		t.Run(strconv.FormatBool(noSSE), func(t *testing.T) {
			raw, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			c := cfg.Config{Kind: "xhttp", Headers: map[string]string{"X-Application": "local"}, XHTTP: &cfg.XHTTP{Mode: "stream-up", NoSSE: noSSE, KeepAlive: cfg.Range{1, 1}, Padding: cfg.Range{4, 4}}}
			ln, e := NewListener(raw, c, nil, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			hc := &http.Client{}
			defer hc.CloseIdleConnections()
			down, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ln.Addr().String()+"/", nil)
			if e := decorate(down, c, "keepalive", "", false, bytes.NewReader(make([]byte, 4096))); e != nil {
				t.Fatal(e)
			}
			dr, e := hc.Do(down)
			if e != nil {
				t.Fatal(e)
			}
			defer dr.Body.Close()
			if (dr.Header.Get("Content-Type") == "text/event-stream") == noSSE || dr.Header.Get("X-Application") != "local" {
				t.Fatal("response controls")
			}
			pr, pw := io.Pipe()
			defer pw.Close()
			upload, _ := http.NewRequestWithContext(ctx, "POST", "http://"+ln.Addr().String()+"/", pr)
			cc := c.Clone()
			cc.XHTTP.NoGRPC = true
			if e := decorate(upload, cc, "keepalive", "", true, bytes.NewReader(make([]byte, 4096))); e != nil {
				t.Fatal(e)
			}
			if upload.Header.Get("Content-Type") != "" {
				t.Fatal("noGRPCHeader")
			}
			ur, e := hc.Do(upload)
			if e != nil {
				t.Fatal(e)
			}
			defer ur.Body.Close()
			p := make([]byte, 4)
			if _, e := io.ReadFull(ur.Body, p); e != nil || string(p) != "XXXX" {
				t.Fatal("initial keepalive", e)
			}
			start := time.Now()
			if _, e := io.ReadFull(ur.Body, p); e != nil || time.Since(start) < 800*time.Millisecond {
				t.Fatal("periodic keepalive", e)
			}
			done := make(chan error, 1)
			go func() { _, e := pw.Write([]byte("application")); done <- e }()
			app, e := ln.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer app.Close()
			app.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, len("application"))
			if _, e := io.ReadFull(app, b); e != nil || string(b) != "application" {
				t.Fatal("keepalive entered application stream", e)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			grpc, _ := http.NewRequest("POST", "http://local/", nil)
			if e := decorate(grpc, c, "", "", true, bytes.NewReader(make([]byte, 4096))); e != nil || grpc.Header.Get("Content-Type") != "application/grpc" {
				t.Fatal("default gRPC header", e)
			}
			app.Close()
			cancel()
			pw.Close()
			dr.Body.Close()
			ur.Body.Close()
			ln.Close()
		})
	}
}

func TestXHTTPWriteDeadlineAndUploadFailure(t *testing.T) {
	cl, l := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up"}}, 2)
	c, e := cl.DialContext(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e := c.Write([]byte("deadline")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("write deadline", e)
	}
	c.SetWriteDeadline(time.Time{})
	exchange(t, c, []byte("recovery"))
	l.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("underlying close ignored")
	}
	cl.Close()
	if len(cl.sessions) != 0 {
		t.Fatal("client session leak")
	}
}

func TestXHTTPTruncatedPacketAndCustomSessionTokens(t *testing.T) {
	r := httptest.NewRequest("POST", "http://local/", bytes.NewBufferString("short"))
	r.ContentLength = 10
	r.Body = io.NopCloser(&truncatedReader{})
	if _, e := packetPayload(r, cfg.Config{Kind: "xhttp"}); e == nil {
		t.Fatal("truncated body accepted")
	}
	seen := map[string]bool{}
	for i := 0; i < 1024; i++ {
		s, e := sessionToken(cfg.XHTTP{SessionTable: "Base62", SessionLength: cfg.Range{32, 32}}, rand.Reader)
		if e != nil || len(s) != 32 || seen[s] {
			t.Fatal("custom token uniqueness", e)
		}
		seen[s] = true
	}
}

type truncatedReader struct{}

func (*truncatedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestXHTTPMissingSequenceExpires(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ln, e := NewListener(raw, cfg.Config{Kind: "xhttp"}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	l := ln.(*Listener)
	defer l.Close()
	s, e := l.allocate("missing-zero")
	if e != nil {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.associated = true
	s.timer.Stop()
	s.mu.Unlock()
	if e := s.enqueue(1, []byte("later")); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	select {
	case <-s.ctx.Done():
		if time.Since(start) < 29*time.Second {
			t.Fatal("gap timer expired prematurely")
		}
	case <-time.After(32 * time.Second):
		t.Fatal("missing sequence retained indefinitely")
	}
	s.close()
	l.Close()
	if l.pending != 0 || len(l.sessions) != 0 {
		t.Fatal("missing sequence resources leaked")
	}
}
func TestXHTTPPacketOrderingMalformedAndBounds(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c := cfg.Config{Kind: "xhttp", Path: "/order", XHTTP: &cfg.XHTTP{Mode: "packet-up", PacketBytes: cfg.Range{16, 16}, Buffered: 2}}
	ln, e := NewListener(raw, c, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	l := ln.(*Listener)
	defer l.Close()
	sid := "order-session"
	request := func(seq, body string) int {
		r := httptest.NewRequest("POST", "http://local/order/"+sid+"/"+seq, bytes.NewBufferString(body))
		if e := decorate(r, c, "", "", false, bytes.NewReader(make([]byte, 4096))); e != nil {
			t.Fatal(e)
		}
		w := httptest.NewRecorder()
		l.ServeHTTP(w, r)
		return w.Code
	}
	if request("1", "B") != 200 || request("0", "A") != 200 {
		t.Fatal("out of order arrival")
	}
	s := l.sessions[sid]
	got := make([]byte, 2)
	s.app.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := io.ReadFull(s.app, got); e != nil || string(got) != "AB" {
		t.Fatal("byte ordering", e, string(got))
	}
	if request("0", "duplicate") != 409 {
		t.Fatal("duplicate delivery")
	}
	if request("bad", "bad") != 400 || request("99999999999999999999999", "overflow") != 400 {
		t.Fatal("sequence parse")
	}
	if request("4", "missing2") != 200 {
		t.Fatal("sequence bounded gap")
	}
	if request("5", "beyond") != 409 {
		t.Fatal("buffer bound")
	}
	if request("2", string(bytes.Repeat([]byte{1}, 17))) != 413 {
		t.Fatal("packet byte bound")
	}
	s.close()
	l.Close()
	if len(l.sessions) != 0 || l.pending != 0 {
		t.Fatal("buffer close leak")
	}
}

func TestXHTTPConcurrentPostsPreserveOneSessionOrdering(t *testing.T) {
	config := cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up"}}
	_, l := fixture(t, config, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hc := &http.Client{}
	defer hc.CloseIdleConnections()
	url := "http://" + l.Addr().String() + "/"
	r, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e := decorate(r, config, "concurrent-posts", "", false, rand.Reader); e != nil {
		t.Fatal(e)
	}
	down, e := hc.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer down.Body.Close()
	errors := make(chan error, 8)
	for seq := 7; seq >= 0; seq-- {
		go func(seq int) {
			if seq == 0 {
				time.Sleep(50 * time.Millisecond)
			}
			r, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bytes.Repeat([]byte{byte(seq)}, 4096)))
			if e := decorate(r, config, "concurrent-posts", strconv.Itoa(seq), false, rand.Reader); e != nil {
				errors <- e
				return
			}
			resp, e := hc.Do(r)
			if e == nil {
				defer resp.Body.Close()
				if resp.StatusCode != 200 {
					e = fmt.Errorf("packet status %d", resp.StatusCode)
				}
			}
			errors <- e
		}(seq)
	}
	for i := 0; i < 8; i++ {
		if e := <-errors; e != nil {
			t.Fatal(e)
		}
	}
	got := make([]byte, 8*4096)
	if _, e := io.ReadFull(down.Body, got); e != nil {
		t.Fatal(e)
	}
	for i, b := range got {
		if b != byte(i/4096) {
			t.Fatal("concurrent packet crossover", i)
		}
	}
}

func TestXHTTPPacketSizeAndMinimumRequestInterval(t *testing.T) {
	config := cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up", PacketBytes: cfg.Range{128, 128}, Interval: cfg.Range{80, 80}}}
	_, l := fixture(t, config, 0)
	times := make(chan time.Time, 4)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if r.ContentLength > 128 {
				t.Error("packet byte limit ignored")
			}
			times <- time.Now()
		}
		l.ServeHTTP(w, r)
	}))
	defer front.Close()
	cl, e := NewClient((&net.Dialer{}).DialContext, strings.TrimPrefix(front.URL, "http://"), config, Security{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer cl.Close()
	c, e := cl.DialContext(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	exchange(t, c, bytes.Repeat([]byte{17}, 512))
	previous := <-times
	for i := 1; i < 4; i++ {
		now := <-times
		if now.Sub(previous) < 65*time.Millisecond {
			t.Fatal("minimum interval ignored", now.Sub(previous))
		}
		previous = now
	}
	c.Close()
	cl.Close()
}
func TestXHTTPTLSAndAdmissionRejection(t *testing.T) {
	cl, l := fixture(t, cfg.Config{Kind: "xhttp"}, 2)
	wrong := cl.security.TLS.Clone()
	wrong.ServerName = "wrong.synthetic.test"
	bad, e := NewClient((&net.Dialer{}).DialContext, l.Addr().String(), cfg.Config{Kind: "xhttp"}, Security{TLS: wrong}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer bad.Close()
	if c, e := bad.DialContext(context.Background()); e == nil {
		c.Close()
		t.Fatal("certificate identity accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c, e := cl.DialContext(ctx); e == nil {
		c.Close()
		t.Fatal("canceled admission")
	}
	if _, e := NewClient((&net.Dialer{}).DialContext, l.Addr().String(), cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "stream-one"}}, Security{}, nil); e == nil {
		t.Fatal("H1 stream-one accepted")
	}
}
func TestXHTTPEnvelopeRobustness(t *testing.T) {
	c := cfg.Config{Kind: "xhttp", Path: "/bound", Host: "core.test"}
	for _, url := range []string{"http://other.test/bound/session/0", "http://core.test/other/session/0", "http://core.test/bound/session/0/extra", "http://core.test/bound/bad%2fsession/0"} {
		t.Run(url, func(t *testing.T) {
			r := httptest.NewRequest("POST", url, nil)
			r.Header.Set("Referer", "http://local/?x_padding="+string(bytes.Repeat([]byte{'X'}, 100)))
			if _, _, e := parseEnvelope(r, c); e == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
	r := httptest.NewRequest("POST", "http://core.test/bound/session/0", nil)
	if _, _, e := parseEnvelope(r, c); e == nil {
		t.Fatal("missing padding")
	}
	for _, method := range []string{"repeat-x", "tokenish"} {
		for _, size := range []int32{1, 64, 100, 1000} {
			t.Run(method+strconv.Itoa(int(size)), func(t *testing.T) {
				x := (cfg.XHTTP{Padding: cfg.Range{size, size}, PaddingMethod: method}).Normalized()
				p, e := padding(x, bytes.NewReader(make([]byte, 10000)))
				if e != nil || p == "" {
					t.Fatal(e)
				}
				r := httptest.NewRequest("GET", "http://core.test/bound/session", nil)
				r.Header.Set("Referer", "http://local/?x_padding="+p)
				cc := c
				cc.XHTTP = &x
				if _, _, e := parseEnvelope(r, cc); e != nil {
					t.Fatal("padding size", e)
				}
			})
		}
	}
}

func TestXHTTPXMUXRetirement(t *testing.T) {
	for _, control := range []string{"concurrency", "connections", "reuse", "requests", "lifetime", "keepalive-disabled"} {
		t.Run(control, func(t *testing.T) {
			m := &cfg.XMUX{MaxConnections: cfg.Range{1, 1}}
			switch control {
			case "concurrency":
				m.MaxConnections = cfg.Range{}
				m.MaxConcurrency = cfg.Range{1, 1}
			case "connections":
				m.MaxConnections = cfg.Range{2, 2}
			case "reuse":
				m.Reuse = cfg.Range{1, 1}
			case "requests":
				m.Requests = cfg.Range{2, 2}
			case "lifetime":
				m.Lifetime = cfg.Range{1, 1}
			case "keepalive-disabled":
				m.KeepAlive = -1
			}
			cl, _ := fixture(t, cfg.Config{Kind: "xhttp", XHTTP: &cfg.XHTTP{Mode: "packet-up", XMUX: m}}, 2)
			a, e := cl.DialContext(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			exchange(t, a, []byte("first"))
			if control == "lifetime" {
				time.Sleep(1100 * time.Millisecond)
			}
			b, e := cl.DialContext(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			exchange(t, b, []byte("second"))
			a.Close()
			exchange(t, b, []byte("other session continues"))
			cl.pool.mu.Lock()
			entries := len(cl.pool.entries)
			cl.pool.mu.Unlock()
			if control != "keepalive-disabled" && entries < 2 {
				t.Fatal("pool limit/retirement not applied", control, entries)
			}
			cl.Close()
			if len(cl.pool.entries) != 0 {
				t.Fatal("pool retained after close")
			}
		})
	}
}

func TestXHTTPDownloadIndependentTargetSecurityAndFailure(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "auto"} {
		for _, secure := range []bool{false, true} {
			for _, failure := range []string{"upload", "download"} {
				t.Run(mode+strconv.FormatBool(secure)+"/"+failure, func(t *testing.T) {
					_, l := fixture(t, cfg.Config{Kind: "xhttp", Path: "/split"}, 2)
					front, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					material := testkit.TLSForName(t, "download.synthetic.test")
					cert, _ := os.ReadFile(material.CertificateFile)
					key, _ := os.ReadFile(material.PrivateKeyFile)
					pair, e := tls.X509KeyPair(cert, key)
					if e != nil {
						t.Fatal(e)
					}
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM([]byte(material.CACertificate))
					server := &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"http/1.1"}}
					var client *tls.Config
					var serving net.Listener = front
					if secure {
						serving = tls.NewListener(front, server)
						client = &tls.Config{ServerName: material.ServerName, RootCAs: roots, NextProtos: []string{"http/1.1"}}
					}
					httpServer := &http.Server{Handler: l, ReadHeaderTimeout: time.Second}
					go httpServer.Serve(serving)
					defer httpServer.Close()
					port := uint16(front.Addr().(*net.TCPAddr).Port)
					kind := "none"
					if secure {
						kind = "tls"
					}
					// Both controlled front doors route to the same session owner, as required
					// for split download deployments; target and security are independent.
					d := cfg.Download{Endpoint: access.Endpoint{Host: "127.0.0.1", Port: port}, Transport: cfg.Config{Kind: "xhttp", Path: "/split"}, Security: kind}
					if secure {
						d.TLS = access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate, ALPN: []string{"http/1.1"}}
					}
					cc := cfg.Config{Kind: "xhttp", Path: "/split", XHTTP: &cfg.XHTTP{Mode: mode, Download: &d}}
					// Use plaintext upload through a second controlled front door while download
					// exercises independently configured plaintext or verified TLS.
					upload, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					uploadServer := &http.Server{Handler: l}
					go uploadServer.Serve(upload)
					defer uploadServer.Close()
					cl, e := NewClient((&net.Dialer{}).DialContext, upload.Addr().String(), cc, Security{}, func(cfg.Download) (Security, error) { return Security{TLS: client}, nil })
					if e != nil {
						t.Fatal(e)
					}
					defer cl.Close()
					c, e := cl.DialContext(context.Background())
					if e != nil {
						t.Fatal(e)
					}
					exchange(t, c, bytes.Repeat([]byte("split legs"), 7000))
					if failure == "download" {
						httpServer.Close()
					} else {
						uploadServer.Close()
						c.SetWriteDeadline(time.Now().Add(time.Second))
						_, _ = c.Write([]byte("failed upload"))
					}
					c.SetReadDeadline(time.Now().Add(3 * time.Second))
					if _, e := c.Read(make([]byte, 1)); e == nil || errors.Is(e, os.ErrDeadlineExceeded) {
						t.Fatal("leg failure did not close logical session", e)
					}
					c.Close()
					cl.Close()
				})
			}
		}
	}
}

func TestXHTTPAssociationAndAggregateResourceBounds(t *testing.T) {
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	ln, e := NewListener(raw, cfg.Config{Kind: "xhttp"}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	l := ln.(*Listener)
	defer l.Close()
	for i := 0; i < sessionLimit; i++ {
		if _, e := l.allocate("pending-" + strconv.Itoa(i)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := l.allocate("overflow"); e == nil {
		t.Fatal("session count unbounded")
	}
	s := l.sessions["pending-0"]
	s.timer.Reset(time.Millisecond)
	select {
	case <-s.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("association timeout did not reap")
	}
	s.close()
	replacement, e := l.allocate("replacement")
	if e != nil {
		t.Fatal(e)
	}
	l.mu.Lock()
	l.pending = totalBytes
	l.mu.Unlock()
	if replacement.enqueue(0, []byte{1}) == nil {
		t.Fatal("aggregate packet budget ignored")
	}
	l.mu.Lock()
	l.pending = 0
	l.mu.Unlock()
	l.Close()
	if len(l.sessions) != 0 || l.pending != 0 {
		t.Fatal("pending sessions survived close")
	}
}
