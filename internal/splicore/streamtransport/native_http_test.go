package streamtransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func nativeTLSFixture(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	m := testkit.TLSForName(t, "native.synthetic.test")
	cert, e := os.ReadFile(m.CertificateFile)
	if e != nil {
		t.Fatal(e)
	}
	key, e := os.ReadFile(m.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(m.CACertificate))
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, &tls.Config{ServerName: m.ServerName, RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func httpFixture(t *testing.T, kind string) (*Client, net.Listener, *atomic.Int32) {
	t.Helper()
	server, client := nativeTLSFixture(t)
	c := cfg.Config{Kind: kind, Path: "/native"}
	raw, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	l, e := WrapListener(raw, c, server)
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	cl, e := NewClient(func(ctx context.Context, n, a string) (net.Conn, error) {
		count.Add(1)
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}, l.Addr().String(), c, ClientSecurity{TLS: client}, nil)
	if e != nil {
		l.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { cl.Close(); l.Close() })
	return cl, l, count
}

func nativeEcho(t *testing.T, cl *Client, l net.Listener, payload []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, e := cl.DialContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan error, 2)
	go func() { _, e := a.Write(payload); done <- e }()
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(b, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("up bytes: %v", e)
	}
	go func() { _, e := b.Write(payload); done <- e }()
	if _, e = io.ReadFull(a, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("down bytes: %v", e)
	}
	for range 2 {
		if e = <-done; e != nil {
			t.Fatal(e)
		}
	}
}

func TestPhase31HTTPDuplex(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, count := httpFixture(t, kind)
			for _, n := range []int{1, 31, 16384, 256 << 10, 2 << 20} {
				nativeEcho(t, cl, l, bytes.Repeat([]byte{byte(n)}, n))
			}
			if kind == "h2" && count.Load() != 1 {
				t.Fatalf("H2 sessions %d", count.Load())
			}
			if kind == "http" && count.Load() != 5 {
				t.Fatalf("H1 sessions %d", count.Load())
			}
		})
	}
}

func TestPhase31HTTPHalfClose(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, _ := httpFixture(t, kind)
			a, e := cl.DialContext(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			b, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			if e = a.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if n, e := b.Read(make([]byte, 1)); n != 0 || e != io.EOF {
				t.Fatalf("EOF: %d %v", n, e)
			}
			done := make(chan error, 1)
			go func() { _, e := b.Write([]byte("reply")); done <- e }()
			got := make([]byte, 5)
			if _, e = io.ReadFull(a, got); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			if e = b.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if n, e := a.Read(make([]byte, 1)); n != 0 || e != io.EOF {
				t.Fatalf("response EOF: %d %v", n, e)
			}
		})
	}
}

func TestPhase31H2ConcurrencyIsolation(t *testing.T) {
	cl, l, count := httpFixture(t, "h2")
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			a, e := cl.DialContext(t.Context())
			if e != nil {
				errs <- e
				return
			}
			defer a.Close()
			a.SetDeadline(time.Now().Add(5 * time.Second))
			payload := bytes.Repeat([]byte{byte(i)}, 32768)
			done := make(chan error, 1)
			go func() { _, e := a.Write(payload); done <- e }()
			got := make([]byte, len(payload))
			_, e = io.ReadFull(a, got)
			if e == nil && !bytes.Equal(payload, got) {
				e = io.ErrUnexpectedEOF
			}
			if we := <-done; e == nil {
				e = we
			}
			errs <- e
		})
	}
	for range n {
		b, e := l.Accept()
		if e != nil {
			t.Fatal(e)
		}
		go func() { defer b.Close(); io.Copy(b, b) }()
	}
	wg.Wait()
	for range n {
		if e := <-errs; e != nil {
			t.Fatal(e)
		}
	}
	if count.Load() != 1 {
		t.Fatalf("physical connections %d", count.Load())
	}
	nativeEcho(t, cl, l, []byte("sibling survives closed streams"))
}

func TestPhase31HTTPRequestAdmission(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		c := cfg.Config{Kind: kind, Path: "/native"}
		for _, tc := range []struct {
			method, path, content string
			want                  int
		}{{"POST", "/native", nativeContentType, 0}, {"GET", "/native", nativeContentType, 405}, {"CONNECT", "/native", nativeContentType, 405}, {"POST", "/native/suffix", nativeContentType, 404}, {"POST", "/native%2f", nativeContentType, 404}, {"POST", "/native?x=1", nativeContentType, 404}, {"POST", "/native", "text/plain", 400}} {
			r, _ := http.NewRequest(tc.method, "https://native.synthetic.test"+tc.path, nil)
			r.RequestURI = tc.path
			r.URL.Scheme = ""
			r.URL.Host = ""
			r.ProtoMajor = 1
			r.ProtoMinor = 1
			if kind == "h2" {
				r.ProtoMajor = 2
			}
			r.ContentLength = -1
			r.Header.Set("Content-Type", tc.content)
			if got := nativeRequestStatus(r, c); got != tc.want {
				t.Fatalf("%s %s got %d want %d", kind, tc.path, got, tc.want)
			}
		}
	}
}

func FuzzPhase31HTTPAdmission(f *testing.F) {
	f.Add("POST", "/native", nativeContentType)
	f.Add("CONNECT", "//native", "bad")
	f.Fuzz(func(t *testing.T, method, path, content string) {
		if len(method)+len(path)+len(content) > 32768 {
			return
		}
		r, e := http.NewRequest(method, "https://native.synthetic.test/", nil)
		if e != nil {
			return
		}
		r.RequestURI = path
		r.ContentLength = -1
		r.Header.Set("Content-Type", content)
		_ = nativeRequestStatus(r, cfg.Config{Kind: "h2", Path: "/native"})
	})
}

func TestPhase31HTTPNegativeTLSAndPath(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			good, l, _ := httpFixture(t, kind)
			base := good.impl.(*httpNativeClient)
			for _, mode := range []string{"wrong-sni", "untrusted", "wrong-path", "wrong-alpn", "cancelled"} {
				t.Run(mode, func(t *testing.T) {
					tc := base.tls.Clone()
					c := base.cfg.Clone()
					switch mode {
					case "wrong-sni":
						tc.ServerName = "wrong.synthetic.test"
					case "untrusted":
						tc.RootCAs = x509.NewCertPool()
					case "wrong-path":
						c.Path += "/suffix"
					case "wrong-alpn":
						tc.NextProtos = []string{"h3"}
					}
					cl, e := NewClient((&net.Dialer{}).DialContext, l.Addr().String(), c, ClientSecurity{TLS: tc}, nil)
					if e != nil {
						if mode != "wrong-alpn" {
							t.Fatal(e)
						}
						return
					}
					defer cl.Close()
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					if mode == "cancelled" {
						cancel()
					}
					conn, e := cl.DialContext(ctx)
					if e == nil {
						conn.Close()
						t.Fatal("invalid transport admitted")
					}
				})
			}
			nativeEcho(t, good, l, []byte("valid sibling after rejection"))
		})
	}
}

func TestPhase31HTTPCloseInterrupts(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, _ := httpFixture(t, kind)
			a, e := cl.DialContext(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			b, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			done := make(chan error, 1)
			go func() { _, e := a.Read(make([]byte, 1)); done <- e }()
			cl.Close()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("read survived close")
				}
			case <-time.After(time.Second):
				t.Fatal("client close left blocked read")
			}
			if _, e = cl.DialContext(t.Context()); e == nil {
				t.Fatal("closed client redialed")
			}
			if e = l.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = l.Accept(); e == nil {
				t.Fatal("closed listener accepted")
			}
		})
	}
}

func TestPhase31StandardHTTPPeers(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			serverTLS, clientTLS := nativeTLSFixture(t)
			standard := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctl := http.NewResponseController(w)
				if r.ProtoMajor == 1 {
					if e := ctl.EnableFullDuplex(); e != nil {
						t.Error(e)
						return
					}
				}
				w.Header().Set("Content-Type", nativeContentType)
				w.WriteHeader(http.StatusOK)
				ctl.Flush()
				buf := make([]byte, 31)
				for {
					n, e := r.Body.Read(buf)
					if n > 0 {
						if _, we := w.Write(buf[:n]); we != nil {
							return
						}
						if ctl.Flush() != nil {
							return
						}
					}
					if e != nil {
						return
					}
				}
			}))
			standard.EnableHTTP2 = kind == "h2"
			standard.TLS = serverTLS
			standard.StartTLS()
			defer standard.Close()
			c := cfg.Config{Kind: kind, Path: "/native"}
			cl, e := NewClient((&net.Dialer{}).DialContext, strings.TrimPrefix(standard.URL, "https://"), c, ClientSecurity{TLS: clientTLS}, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer cl.Close()
			a, e := cl.DialContext(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			for i := range 100 {
				want := bytes.Repeat([]byte{byte(i)}, 17)
				if _, e = a.Write(want); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(want))
				if _, e = io.ReadFull(a, got); e != nil || !bytes.Equal(want, got) {
					t.Fatal("standard streaming peer", i, e)
				}
			}
			if e = a.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if _, e = io.ReadAll(a); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestPhase31H2SessionLoss(t *testing.T) {
	cl, l, count := httpFixture(t, "h2")
	nativeEcho(t, cl, l, []byte("first"))
	impl := cl.impl.(*httpNativeClient)
	impl.mu.Lock()
	cc := impl.h2
	impl.mu.Unlock()
	cc.Close()
	nativeEcho(t, cl, l, []byte("after connection failure"))
	if count.Load() != 2 {
		t.Fatal("stale H2 session not evicted", count.Load())
	}
}

func TestPhase31H2ActiveResetIsolation(t *testing.T) {
	cl, l, _ := httpFixture(t, "h2")
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	a.Close()
	nativeEcho(t, cl, l, []byte("active sibling after RST_STREAM"))
}

func nativeSimultaneous(t *testing.T, cl *Client, l net.Listener) {
	t.Helper()
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = a.Write([]byte{1}); e != nil {
		t.Fatal(e)
	}
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = io.ReadFull(b, make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	up, down := bytes.Repeat([]byte{'U'}, 2<<20), bytes.Repeat([]byte{'D'}, 2<<20)
	done := make(chan error, 4)
	go func() { _, e := a.Write(up); done <- e }()
	go func() { _, e := b.Write(down); done <- e }()
	go func() {
		got := make([]byte, len(up))
		_, e := io.ReadFull(b, got)
		if e == nil && !bytes.Equal(got, up) {
			e = io.ErrUnexpectedEOF
		}
		done <- e
	}()
	go func() {
		got := make([]byte, len(down))
		_, e := io.ReadFull(a, got)
		if e == nil && !bytes.Equal(got, down) {
			e = io.ErrUnexpectedEOF
		}
		done <- e
	}()
	for range 4 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}

func TestPhase31HTTPSimultaneous(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) { cl, l, _ := httpFixture(t, kind); nativeSimultaneous(t, cl, l) })
	}
}

func TestPhase31HTTPDeadlineIsolation(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, _ := httpFixture(t, kind)
			a, e := cl.DialContext(t.Context())
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			b, e := l.Accept()
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			a.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, e = a.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal("deadline", e)
			}
			nativeEcho(t, cl, l, []byte("sibling unaffected by deadline"))
		})
	}
}

func TestPhase31HTTPRejectsUnreadBody(t *testing.T) {
	cl, l, _ := httpFixture(t, "http")
	tc := cl.impl.(*httpNativeClient).tls.Clone()
	raw, e := tls.Dial("tcp", l.Addr().String(), tc)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	if _, e = io.WriteString(raw, "CONNECT /native HTTP/1.1\r\nHost: native.synthetic.test\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"); e != nil {
		t.Fatal(e)
	}
	response, e := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal(response.StatusCode)
	}
	if _, e = io.ReadAll(response.Body); e != nil {
		t.Fatal(e)
	}
	var b [1]byte
	if _, e = raw.Read(b[:]); e == nil {
		t.Fatal("rejected unread body retained connection")
	}
	if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
		t.Fatal("rejection waited for unread body", e)
	}
}
