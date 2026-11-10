package remotesource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
)

type fetchContextKey struct{}
type observedFetchNetwork struct {
	dial   func(context.Context, access.Endpoint) (net.Conn, error)
	calls  atomic.Int64
	closed chan struct{}
}

func (n *observedFetchNetwork) Resolve(_ context.Context, h string) ([]netip.Addr, error) {
	ip, e := netip.ParseAddr(h)
	if e != nil {
		return nil, errors.New("unexpected ambient hostname")
	}
	return []netip.Addr{ip}, nil
}
func (n *observedFetchNetwork) Dial(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	n.calls.Add(1)
	if n.dial != nil {
		return n.dial(ctx, e)
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
	if err != nil {
		return nil, err
	}
	return &observedFetchConn{Conn: raw, closed: n.closed}, nil
}

type observedFetchConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *observedFetchConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() {
		if c.closed != nil {
			c.closed <- struct{}{}
		}
	})
	return e
}
func fetchWait(t *testing.T, c <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("wait", label)
	}
}
func TestProviderFetchDeadlineAndCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		if !t.Run(mode, func(t *testing.T) {
			duration := 5 * time.Second
			if mode == "deadline" {
				duration = time.Second
			}
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), fetchContextKey{}, mode), duration)
			defer cancel()
			expected, _ := ctx.Deadline()
			entered := make(chan struct{})
			exited := make(chan struct{})
			n := &observedFetchNetwork{dial: func(ctx context.Context, _ access.Endpoint) (net.Conn, error) {
				deadline, ok := ctx.Deadline()
				if !ok || !deadline.Equal(expected) || ctx.Value(fetchContextKey{}) != mode {
					t.Error("request context was detached")
				}
				close(entered)
				<-ctx.Done()
				close(exited)
				return nil, ctx.Err()
			}}
			done := make(chan error, 1)
			go func() {
				_, e := Fetch(ctx, n, provider.Provider{AllowPrivate: true}, provider.Source{URL: "http://127.0.0.1:1"})
				done <- e
			}()
			fetchWait(t, entered, "dial")
			if mode == "cancel" {
				cancel()
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("canceled fetch succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("fetch ignored cancellation")
			}
			fetchWait(t, exited, "dial exit")
			if n.calls.Load() != 1 {
				t.Fatal("unexpected retry", n.calls.Load())
			}
		}) {
			return
		}
	}
}
func TestProviderFetchProtectedFailureHasNoDefaultFallback(t *testing.T) {
	var hits, connects atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer server.Close()
	n := &observedFetchNetwork{dial: func(context.Context, access.Endpoint) (net.Conn, error) {
		return nil, errors.New("synthetic protected refusal")
	}}
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{ConnectStart: func(string, string) { connects.Add(1) }})
	_, e := Fetch(ctx, n, provider.Provider{AllowPrivate: true}, provider.Source{URL: server.URL})
	if e == nil || n.calls.Load() != 1 || hits.Load() != 0 || connects.Load() != 0 {
		t.Fatal("default exit or failure swallowed", e, n.calls.Load(), hits.Load(), connects.Load())
	}
}
func TestProviderFetchRedirectAndCache(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	for _, status := range []int{301, 302, 307, 308} {
		if !t.Run(strconv.Itoa(status), func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("If-None-Match") != "" {
					t.Error("cross-origin headers leaked")
				}
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "redirect fixture")
			}))
			defer target.Close()
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer SYNTHETIC" {
					t.Error("initial auth missing")
				}
				http.Redirect(w, r, target.URL, status)
			}))
			defer origin.Close()
			n := &observedFetchNetwork{closed: make(chan struct{}, 4)}
			result, e := Fetch(context.Background(), n, provider.Provider{AllowPrivate: true}, provider.Source{URL: origin.URL, Auth: &provider.Auth{Type: "bearer", Value: "SYNTHETIC"}, ETag: "old-cache"})
			if e != nil || string(result.Body) != "redirect fixture" || n.calls.Load() != 2 {
				t.Fatal("redirect policy", e, n.calls.Load())
			}
			fetchWait(t, n.closed, "origin close")
			fetchWait(t, n.closed, "target close")
		}) {
			return
		}
	}
	cache := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"synthetic-v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"synthetic-v1"`)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "cache fixture")
	}))
	defer cache.Close()
	n := &observedFetchNetwork{closed: make(chan struct{}, 4)}
	source := provider.Source{URL: cache.URL}
	first, e := Fetch(context.Background(), n, provider.Provider{AllowPrivate: true}, source)
	if e != nil {
		t.Fatal(e)
	}
	source.ETag = first.ETag
	second, e := Fetch(context.Background(), n, provider.Provider{AllowPrivate: true}, source)
	if e != nil || !second.NotModified || len(second.Body) != 0 || n.calls.Load() != 2 {
		t.Fatal("304/cache", e, second.NotModified, n.calls.Load())
	}
	fetchWait(t, n.closed, "first cache body close")
	fetchWait(t, n.closed, "304 body close")
}
func TestProviderFetchResponseBodyCancellation(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(exited)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		close(entered)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n := &observedFetchNetwork{closed: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		_, e := Fetch(ctx, n, provider.Provider{AllowPrivate: true}, provider.Source{URL: server.URL})
		done <- e
	}()
	fetchWait(t, entered, "response body")
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("partial body accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("body read did not cancel")
	}
	fetchWait(t, n.closed, "connection close")
	fetchWait(t, exited, "HTTP worker exit")
}
func TestProviderFetchConcurrentContexts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, r.URL.Path)
	}))
	defer server.Close()
	const count = 8
	closed := make(chan struct{}, count)
	errch := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), fetchContextKey{}, i), 5*time.Second)
			defer cancel()
			n := &observedFetchNetwork{closed: closed}
			n.dial = func(ctx context.Context, e access.Endpoint) (net.Conn, error) {
				if ctx.Value(fetchContextKey{}) != i {
					return nil, errors.New("fetch contexts crossed")
				}
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
				if err != nil {
					return nil, err
				}
				return &observedFetchConn{Conn: raw, closed: closed}, nil
			}
			result, e := Fetch(ctx, n, provider.Provider{AllowPrivate: true}, provider.Source{URL: fmt.Sprintf("%s/%d", server.URL, i)})
			if e != nil || string(result.Body) != fmt.Sprintf("/%d", i) || n.calls.Load() != 1 {
				errch <- fmt.Errorf("concurrent fetch %d: %v", i, e)
			}
		}(i)
	}
	wg.Wait()
	close(errch)
	for e := range errch {
		t.Error(e)
	}
	for range count {
		fetchWait(t, closed, "concurrent socket cleanup")
	}
}
