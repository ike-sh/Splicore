package hysteria

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/http/httputil"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type masqueradeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f masqueradeRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The protected mock uses pipes, so any TCP ConnectStart, ambient DNS query,
// or use of the process-default transport is an unintended fallback.
func observeMasqueradeDefaults(t *testing.T) *atomic.Int64 {
	t.Helper()
	var calls atomic.Int64
	resolver, transport := net.DefaultResolver, http.DefaultTransport
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected ambient DNS")
	}}
	http.DefaultTransport = masqueradeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected default transport")
	})
	t.Cleanup(func() {
		net.DefaultResolver, http.DefaultTransport = resolver, transport
		if n := calls.Load(); n != 0 {
			t.Errorf("ordinary default dial/DNS/transport calls=%d", n)
		}
	})
	return &calls
}

func masqueradeRequest(ctx context.Context, path string, defaults *atomic.Int64) *http.Request {
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{ConnectStart: func(string, string) { defaults.Add(1) }})
	return httptest.NewRequest("GET", "https://front.invalid"+path, nil).WithContext(ctx)
}

// Only the test peer creates a goroutine. The production dialer receives a
// normal connection and the standard HTTP pool can reuse it across requests.
func masqueradePipe(t *testing.T, tc *tls.Config, reply func(*http.Request) (int, http.Header, string)) (net.Conn, <-chan struct{}) {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		var peer net.Conn = server
		if tc != nil {
			peer = tls.Server(server, tc)
		}
		reader := bufio.NewReader(peer)
		for {
			r, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			status, header, body := reply(r)
			response := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: header, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r}
			err = response.Write(peer)
			_ = response.Body.Close()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("masquerade upstream peer survived cleanup")
		}
	})
	return client, done
}

func TestMasqueradeProtectedDialAndNoDefault(t *testing.T) {
	defaults := observeMasqueradeDefaults(t)
	st, ct := material(t)
	for _, scheme := range []string{"http", "https"} {
		for _, host := range []string{"127.0.0.1", "::1", ct.ServerName} {
			t.Run(scheme+"/"+host, func(t *testing.T) {
				address := net.JoinHostPort(host, "8443")
				var dials atomic.Int64
				type requestKey struct{}
				ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), requestKey{}, "owned-request"), 3*time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				var peerDone <-chan struct{}
				h, cleanup, err := masquerade(&cfg.Masquerade{Type: "proxy", URL: scheme + "://" + address + "/base?up=1", RewriteHost: true, Insecure: host != ct.ServerName}, func(call context.Context, network, target string) (net.Conn, error) {
					dials.Add(1)
					got, ok := call.Deadline()
					if network != "tcp" || target != address || call.Value(requestKey{}) != "owned-request" || !ok || !got.Equal(deadline) {
						t.Errorf("protected dial arguments/context: %s %s deadline=%v", network, target, got)
					}
					var tc *tls.Config
					if scheme == "https" {
						tc = st
					}
					c, done := masqueradePipe(t, tc, func(r *http.Request) (int, http.Header, string) {
						if r.Host != address || r.URL.RequestURI() != "/base/child?up=1&client=2" {
							t.Errorf("target changed: %s %s", r.Host, r.URL)
						}
						return 200, nil, "protected-response"
					})
					peerDone = done
					return c, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(cleanup)
				proxy := h.(*httputil.ReverseProxy)
				proxy.Transport.(masqueradeTransport).TLSClientConfig.RootCAs = ct.RootCAs
				for range 2 {
					w := httptest.NewRecorder()
					h.ServeHTTP(w, masqueradeRequest(ctx, "/child?client=2", defaults))
					if w.Code != 200 || w.Body.String() != "protected-response" {
						t.Fatal(w.Code, w.Body.String())
					}
				}
				if dials.Load() != 1 {
					t.Fatal("HTTP pool did not reuse approved connection", dials.Load())
				}
				cleanup()
				select {
				case <-peerDone:
				case <-ctx.Done():
					t.Fatal("idle upstream survived owner Close")
				}
			})
		}
	}
}

func TestMasqueradeFailClosedAndInitializationRollback(t *testing.T) {
	defaults := observeMasqueradeDefaults(t)
	m := &cfg.Masquerade{Type: "proxy", URL: "http://unresolved.invalid/"}
	if h, closeMask, err := masquerade(m, nil); !errors.Is(err, ErrConfig) || h != nil || closeMask != nil {
		t.Fatal("missing capability accepted", err)
	}
	st, _ := material(t)
	p, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewServer(context.Background(), p, ServerConfig{TLS: st, Settings: cfg.Hysteria{Version: 2, Masquerade: m}, Authenticate: func(string) (string, bool) { return "A", true }, Application: func(*Connection) Hooks { return Hooks{} }})
	if !errors.Is(err, ErrConfig) {
		t.Fatal("server accepted missing proxy capability", err)
	}
	if _, err = p.WriteTo([]byte{1}, p.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("initialization leaked carrier", err)
	}
	sentinel := errors.New("protected route refused")
	var calls atomic.Int64
	h, cleanup, err := masquerade(m, func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, sentinel })
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	proxy := h.(*httputil.ReverseProxy)
	original := proxy.ErrorHandler
	var cause error
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) { cause = err; original(w, r, err) }
	w := httptest.NewRecorder()
	h.ServeHTTP(w, masqueradeRequest(context.Background(), "/", defaults))
	if w.Code != 502 || w.Body.String() != "Bad Gateway\n" || !errors.Is(cause, sentinel) || calls.Load() != 1 {
		t.Fatal("failure hidden or retried", w.Code, cause, calls.Load())
	}
}

func TestMasqueradeDialCancellationDeadlineAndClose(t *testing.T) {
	defaults := observeMasqueradeDefaults(t)
	for _, mode := range []string{"cancel", "deadline", "owner-close"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			}
			defer cancel()
			entered, exited, handled := make(chan context.Context, 1), make(chan error, 1), make(chan struct{})
			h, cleanup, err := masquerade(&cfg.Masquerade{Type: "proxy", URL: "http://no-fallback.invalid/"}, func(call context.Context, _, _ string) (net.Conn, error) {
				entered <- call
				<-call.Done()
				exited <- call.Err()
				return nil, call.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			go func() {
				defer close(handled)
				h.ServeHTTP(httptest.NewRecorder(), masqueradeRequest(ctx, "/", defaults))
			}()
			select {
			case call := <-entered:
				got, ok := call.Deadline()
				if !ok || time.Until(got) > 5*time.Second {
					t.Fatal("dial admission unbounded")
				}
				if want, ok := ctx.Deadline(); ok && !want.Equal(got) {
					t.Fatal("request deadline lost", got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("protected dial not entered")
			}
			if mode == "cancel" {
				cancel()
			}
			if mode == "owner-close" {
				cleanup()
			}
			want := context.Canceled
			if mode == "deadline" {
				want = context.DeadlineExceeded
			}
			select {
			case err := <-exited:
				if !errors.Is(err, want) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("dial not canceled")
			}
			select {
			case <-handled:
			case <-time.After(5 * time.Second):
				t.Fatal("request survived cancellation")
			}
		})
	}
}

func TestMasqueradeTLSCancellationAndVerification(t *testing.T) {
	defaults := observeMasqueradeDefaults(t)
	for _, mode := range []string{"cancel-handshake", "verify-certificate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, closed := make(chan struct{}), make(chan struct{})
			st, _ := material(t)
			var listener *net.TCPListener
			if mode == "verify-certificate" {
				var err error
				listener, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			h, cleanup, err := masquerade(&cfg.Masquerade{Type: "proxy", URL: "https://wrong.invalid/"}, func(context.Context, string, string) (net.Conn, error) {
				var client, server net.Conn
				if listener == nil {
					client, server = net.Pipe()
				} else {
					// Certificate rejection sends an alert while the server may still
					// be writing its flight. An unbuffered pipe can deadlock these
					// simultaneous writes; use an owned numeric TCP test peer here.
					var err error
					client, err = net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
					if err != nil {
						return nil, err
					}
					server, err = listener.Accept()
					if err != nil {
						_ = client.Close()
						return nil, err
					}
				}
				go func() {
					defer close(closed)
					defer server.Close()
					close(entered)
					if mode == "cancel-handshake" {
						_, _ = io.Copy(io.Discard, server)
					} else {
						_ = tls.Server(server, st).Handshake()
					}
				}()
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			proxy := h.(*httputil.ReverseProxy)
			original := proxy.ErrorHandler
			causes := make(chan error, 1)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) { causes <- err; original(w, r, err) }
			done := make(chan int, 1)
			go func() {
				w := httptest.NewRecorder()
				h.ServeHTTP(w, masqueradeRequest(ctx, "/", defaults))
				done <- w.Code
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("TLS dial not entered")
			}
			if mode == "cancel-handshake" {
				cancel()
			}
			select {
			case code := <-done:
				if code != 502 {
					t.Fatal(code)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("TLS request stalled")
			}
			cause := <-causes
			var verification *tls.CertificateVerificationError
			if mode == "verify-certificate" && !errors.As(cause, &verification) || mode == "cancel-handshake" && !errors.Is(cause, context.Canceled) {
				t.Fatal("TLS failure cause lost", cause)
			}
			cleanup()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("failed TLS retained upstream")
			}
		})
	}
}

func TestMasqueradeConcurrentRequestsAndRedirect(t *testing.T) {
	defaults := observeMasqueradeDefaults(t)
	var dials atomic.Int64
	var mu sync.Mutex
	var peers []<-chan struct{}
	h, cleanup, err := masquerade(&cfg.Masquerade{Type: "proxy", URL: "http://protected.invalid/"}, func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		c, done := masqueradePipe(t, nil, func(r *http.Request) (int, http.Header, string) {
			if r.URL.Path == "/redirect" {
				return 302, http.Header{"Location": []string{"http://must-not-dial.invalid/"}}, "redirect-response"
			}
			return 200, nil, r.URL.Path
		})
		mu.Lock()
		peers = append(peers, done)
		mu.Unlock()
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	var workers sync.WaitGroup
	for i := range 32 {
		workers.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			path := fmt.Sprintf("/request-%d", i)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, masqueradeRequest(ctx, path, defaults))
			if w.Code != 200 || w.Body.String() != path {
				t.Errorf("crossed response: %d %s", w.Code, w.Body.String())
			}
		})
	}
	workers.Wait()
	before := dials.Load()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, masqueradeRequest(context.Background(), "/redirect", defaults))
	if w.Code != 302 || w.Header().Get("Location") != "http://must-not-dial.invalid/" || w.Body.String() != "redirect-response" || dials.Load() != before {
		t.Fatal("redirect followed or pool not reused", w.Code, dials.Load(), before)
	}
	cleanup()
	mu.Lock()
	all := append([]<-chan struct{}(nil), peers...)
	mu.Unlock()
	for _, done := range all {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent upstream survived Close")
		}
	}
	if before < 1 || before > 32 {
		t.Fatal("unexpected socket count", before)
	}
	if _, _, err := masquerade(&cfg.Masquerade{Type: "404"}, nil); err != nil {
		t.Fatal("404 now requires a dialer", err)
	}
}
