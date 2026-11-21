package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func httpFixture(t *testing.T, ctx context.Context, authorize func(context.Context, access.Binding) bool) (*httpProxyHandle, ports.RuntimeIntent, string) {
	t.Helper()
	in := socks5Intent(t)
	in.Inbound.Protocol = proxy.Key("http")
	in.Inbound.Settings.Data = json.RawMessage(`{"auth":true}`)
	in.AuthorizeBinding = authorize
	compiled, err := (HTTPCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := compiled.(*httpProxyHandle)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := h.Close(closeCtx); err != nil {
			t.Error(err)
		}
	})
	pair, err := proxy.Pair(in.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	auth := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(pair.Username+":"+pair.Password)) + "\r\n"
	return h, in, auth
}

func startHTTPFixture(t *testing.T, h *httpProxyHandle) string {
	t.Helper()
	if err := h.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	return h.listener.Addr().String()
}

func httpSocket(t *testing.T, addr string) *net.TCPConn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn.(*net.TCPConn)
}

func sendHTTP(t *testing.T, conn net.Conn, request string) {
	t.Helper()
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal("could not write fixture HTTP bytes:", err)
	}
}

func readHTTP(t *testing.T, reader *bufio.Reader, method string, status int) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(reader, &http.Request{Method: method})
	if err != nil {
		t.Fatal("could not parse HTTP response:", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != status {
		t.Fatalf("HTTP status %d, want %d", resp.StatusCode, status)
	}
	return resp
}

func TestManagedHTTPRejectedWithoutTarget(t *testing.T) {
	var routes atomic.Int64
	var allowed atomic.Bool
	allowed.Store(true)
	ctx := underlay.WithFactory(t.Context(), underlay.New())
	ctx = ports.WithTargetRouter(ctx, func(ctx context.Context, network, address string, fallback ports.TargetDialer) (net.Conn, error) {
		routes.Add(1)
		return fallback.DialContext(ctx, network, address)
	})
	h, _, auth := httpFixture(t, ctx, func(context.Context, access.Binding) bool { return allowed.Load() })
	addr := startHTTPFixture(t, h)
	const get = "GET http://must-not-resolve.invalid/ HTTP/1.1\r\nHost: must-not-resolve.invalid\r\n"
	basic := func(s string) string {
		return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(s)) + "\r\n"
	}
	for _, tc := range []struct {
		name, request string
		status        int
	}{
		{"missing-credentials", get + "\r\n", 407},
		{"wrong-user", get + basic("unknown:incorrect") + "\r\n", 407},
		{"wrong-password", get + basic("Alice:incorrect") + "\r\n", 407},
		{"conflicting-host", "GET http://must-not-resolve.invalid/ HTTP/1.1\r\nHost: other.invalid\r\n" + auth + "\r\n", 400},
		{"missing-host", "GET http://must-not-resolve.invalid/ HTTP/1.1\r\n" + auth + "\r\n", 400},
		{"header-injection", get + auth + "X-Bad: x\rX-Injected: y\r\n\r\n", 400},
		{"bare-lf", get + auth + "X-Bad: value\n\r\n", 400},
		{"repeated-auth", get + auth + auth + "\r\n", 400},
		{"duplicate-content-length", get + auth + "Content-Length: 0\r\nContent-Length: 0\r\n\r\n", 400},
		{"conflicting-framing", get + auth + "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n", 400},
		{"unsupported-transfer-coding", get + auth + "Transfer-Encoding: gzip, chunked\r\n\r\n", 400},
		{"header-bound", get + auth + "X-Large: " + strings.Repeat("a", httpproxy.MaxLine) + "\r\n\r\n", 400},
		{"origin-form", "GET / HTTP/1.1\r\nHost: example.invalid\r\n" + auth + "\r\n", 400},
		{"userinfo", "GET http://user:pass@example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n" + auth + "\r\n", 400},
		{"https-absolute-form", "GET https://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n" + auth + "\r\n", 400},
		{"empty-port", "GET http://example.invalid:/ HTTP/1.1\r\nHost: example.invalid:\r\n" + auth + "\r\n", 400},
		{"invalid-connect", "CONNECT [example.invalid]:443 HTTP/1.1\r\nHost: [example.invalid]:443\r\n" + auth + "\r\n", 400},
		{"upgrade", get + auth + "Connection: close, Upgrade\r\nUpgrade: websocket\r\n\r\n", 501},
		{"invalid-expectation", get + auth + "Expect: unsupported\r\n\r\n", 417},
		{"literal-self-target", fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s\r\n%s\r\n", addr, auth), 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := httpSocket(t, addr)
			defer conn.Close()
			sendHTTP(t, conn, tc.request)
			resp := readHTTP(t, bufio.NewReader(conn), "GET", tc.status)
			if !resp.Close || tc.status == 407 && resp.Header.Get("Proxy-Authenticate") != `Basic realm="Splicore"` {
				t.Fatal("rejection did not close the connection or use the Basic proxy challenge")
			}
			if routes.Load() != 0 {
				t.Fatal("rejected request reached Core target routing")
			}
		})
	}
	allowed.Store(false)
	conn := httpSocket(t, addr)
	sendHTTP(t, conn, get+auth+"\r\n")
	readHTTP(t, bufio.NewReader(conn), "GET", 407)
	if stats := h.Stats(); stats.Sessions != 0 || routes.Load() != 0 {
		t.Fatal("ineligible binding reached target routing or acquired a session")
	}
}

func TestManagedHTTPForwardingStreamsAndSanitizes(t *testing.T) {
	fixture := testkit.NewUnderlay(t)
	mode, err := fixture.Factory.Begin(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer mode.Close()
	h, in, auth := httpFixture(t, underlay.WithFactory(t.Context(), fixture.Factory), func(context.Context, access.Binding) bool { return true })
	addr := startHTTPFixture(t, h)
	remainder := strings.Repeat("0123456789abcdef", 8192)
	uploadStarted, responseTail := make(chan struct{}), make(chan struct{})
	originResult := make(chan error, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originResult <- func() error {
			first := make([]byte, 5)
			if _, err := io.ReadFull(r.Body, first); err != nil || string(first) != "first" {
				return errors.New("origin did not receive first streamed upload chunk")
			}
			close(uploadStarted)
			tail, err := io.ReadAll(io.LimitReader(r.Body, int64(len(remainder)+1)))
			if err != nil || !bytes.Equal(tail, []byte(remainder)) || r.RequestURI != "/stream?x=a%2Bb" ||
				r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" ||
				r.Trailer.Get("X-Valid") != "upload" || r.Trailer.Get("Proxy-Authorization") != "" || r.Trailer.Get("X-Hop") != "" ||
				r.Header.Get("X-End-To-End") != "preserved" {
				return errors.New("origin request framing, payload or field policy differed")
			}
			w.Header().Set("X-Result", "from-origin")
			w.Header().Set("Connection", "close, X-Hop")
			w.Header().Set("X-Hop", "strip")
			w.Header().Set("Proxy-Authenticate", "strip")
			w.Header().Set("Trailer", "X-Result-Trailer, X-Hop")
			w.WriteHeader(201)
			_, _ = io.WriteString(w, "first")
			w.(http.Flusher).Flush()
			select {
			case <-responseTail:
			case <-r.Context().Done():
				return r.Context().Err()
			}
			_, err = io.WriteString(w, remainder)
			w.Header().Set("X-Result-Trailer", "complete")
			w.Header().Set("X-Hop", "strip-this-trailer")
			return err
		}()
	}))
	defer origin.Close()
	conn := httpSocket(t, addr)
	defer conn.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	sendHTTP(t, conn, fmt.Sprintf("POST %s/stream?x=a%%2Bb HTTP/1.1\r\nHost: %s\r\n%sConnection: X-Hop\r\nX-Hop: strip\r\nX-End-To-End: preserved\r\nTransfer-Encoding: chunked\r\nTrailer: X-Valid, Proxy-Authorization, X-Hop\r\nExpect: 100-continue\r\n\r\n", origin.URL, host, auth))
	reader := bufio.NewReader(conn)
	readHTTP(t, reader, "POST", 100)
	sendHTTP(t, conn, "5\r\nfirst\r\n")
	select {
	case <-uploadStarted:
	case err := <-originResult:
		t.Fatal(err)
	case <-time.After(4 * time.Second):
		t.Fatal("proxy buffered the complete upload before forwarding")
	}
	sendHTTP(t, conn, fmt.Sprintf("%x\r\n%s\r\n0\r\nX-Valid: upload\r\nProxy-Authorization: strip\r\nX-Hop: strip\r\n\r\n", len(remainder), remainder))
	resp := readHTTP(t, reader, "POST", 201)
	first := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "first" {
		t.Fatal("proxy buffered or lost first response chunk:", err)
	}
	close(responseTail)
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(remainder)+1)))
	if err != nil || string(data) != remainder || !resp.Close || resp.Header.Get("X-Result") != "from-origin" ||
		resp.Header.Get("X-Hop") != "" || resp.Header.Get("Proxy-Authenticate") != "" ||
		resp.Trailer.Get("X-Result-Trailer") != "complete" || resp.Trailer.Get("X-Hop") != "" {
		t.Fatal("response framing, stream, headers or trailers differed:", err)
	}
	select {
	case err = <-originResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("origin did not complete")
	}
	stats := h.BindingStats(in.Bindings[0].ID)
	want := int64(len(remainder) + 5)
	if stats.Upload != want || stats.Download != want || stats.TCPSessions != 1 ||
		h.BindingStats(in.Bindings[1].ID).Sessions != 0 || fixture.Backend.Count(underlay.ServerTarget) != 1 {
		t.Fatal("payload attribution or protected socket count mismatch")
	}
}

func TestManagedHTTPForwardingBoundaries(t *testing.T) {
	h, _, auth := httpFixture(t, underlay.WithFactory(t.Context(), underlay.New()), func(context.Context, access.Binding) bool { return true })
	addr := startHTTPFixture(t, h)
	var hits atomic.Int64
	canceled, entered := make(chan struct{}), make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/stall":
			close(entered)
			<-r.Context().Done()
			close(canceled)
		case "/short":
			_, _ = io.Copy(io.Discard, r.Body)
		default:
			_, _ = io.WriteString(w, r.URL.Path)
		}
	}))
	defer origin.Close()
	host := strings.TrimPrefix(origin.URL, "http://")
	request := func(method, path string) string {
		return fmt.Sprintf("%s %s%s HTTP/1.1\r\nHost: %s\r\n%s", method, origin.URL, path, host, auth)
	}
	t.Run("connection-close", func(t *testing.T) {
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, request("GET", "/first")+"\r\n"+request("GET", "/second")+"\r\n")
		reader := bufio.NewReader(conn)
		resp := readHTTP(t, reader, "GET", 200)
		b, err := io.ReadAll(resp.Body)
		_, end := reader.ReadByte()
		if err != nil || string(b) != "/first" || end != io.EOF || !resp.Close || hits.Load() != 1 {
			t.Fatal("pipelined bytes crossed one-request boundary or close was not advertised", err, end)
		}
	})
	t.Run("truncated-upload", func(t *testing.T) {
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, request("POST", "/short")+"Content-Length: 8\r\n\r\nabc")
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		readHTTP(t, bufio.NewReader(conn), "POST", 400)
	})
	t.Run("client-cancellation", func(t *testing.T) {
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, request("GET", "/stall")+"\r\n")
		select {
		case <-entered:
		case <-time.After(4 * time.Second):
			t.Fatal("origin did not receive request")
		}
		_ = conn.Close()
		select {
		case <-canceled:
		case <-time.After(4 * time.Second):
			t.Fatal("disconnect did not cancel origin")
		}
	})
}

func TestManagedHTTPConnectionBoundsAndCancellation(t *testing.T) {
	ctx := underlay.WithFactory(t.Context(), underlay.New())
	h, _, auth := httpFixture(t, ctx, func(context.Context, access.Binding) bool { return true })
	h.headerTimeout = 150 * time.Millisecond
	addr := startHTTPFixture(t, h)
	t.Run("slow-header", func(t *testing.T) {
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, "GET http://")
		readHTTP(t, bufio.NewReader(conn), "GET", 408)
	})
	t.Run("unavailable-target", func(t *testing.T) {
		lease, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		target := lease.Addr().String()
		_ = lease.Close()
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s\r\n%s\r\n", target, auth))
		readHTTP(t, bufio.NewReader(conn), "CONNECT", 502)
	})
	t.Run("resolved-self-target", func(t *testing.T) {
		target := net.JoinHostPort("localhost", portString(h.endpoint.Port))
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s\r\n%s\r\n", target, auth))
		readHTTP(t, bufio.NewReader(conn), "CONNECT", 403)
	})

	t.Run("total-limit-and-idle-tunnel", func(t *testing.T) {
		target := testfixture.TCP(t).Addr().String()
		h, _, auth := httpFixture(t, ctx, func(context.Context, access.Binding) bool { return true })
		h.limits = managedProxyLimits{connections: 1, handshakes: 2, perSource: 2}
		h.idleTimeout = time.Second
		addr := startHTTPFixture(t, h)
		conn := httpSocket(t, addr)
		sendHTTP(t, conn, fmt.Sprintf("CONNECT %[1]s HTTP/1.1\r\nHost: %[1]s\r\n%s\r\n", target, auth))
		reader := bufio.NewReader(conn)
		readHTTP(t, reader, "CONNECT", 200)
		extra := httpSocket(t, addr)
		if _, err := extra.Read(make([]byte, 1)); err == nil || httpProxyTimedOut(err) {
			t.Fatal("total connection limit did not refuse a second socket:", err)
		}
		if _, err := reader.ReadByte(); err == nil || httpProxyTimedOut(err) {
			t.Fatal("idle CONNECT did not release its sockets:", err)
		}
	})

	t.Run("bounded-admission-and-pending-dial-cancel", func(t *testing.T) {
		entered, canceled := make(chan struct{}, 2), make(chan struct{}, 2)
		routed := ports.WithTargetRouter(ctx, func(ctx context.Context, _, _ string, _ ports.TargetDialer) (net.Conn, error) {
			entered <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			return nil, ctx.Err()
		})
		h, _, auth := httpFixture(t, routed, func(context.Context, access.Binding) bool { return true })
		h.limits = managedProxyLimits{connections: 2, handshakes: 2, perSource: 1}
		addr := startHTTPFixture(t, h)
		open := func() *net.TCPConn {
			conn := httpSocket(t, addr)
			sendHTTP(t, conn, "CONNECT pending.invalid:443 HTTP/1.1\r\nHost: pending.invalid:443\r\n"+auth+"\r\n")
			return conn
		}
		client := open()
		select {
		case <-entered:
		case <-time.After(4 * time.Second):
			t.Fatal("protected dial was not reached")
		}
		extra := httpSocket(t, addr)
		var b [1]byte
		if n, err := extra.Read(b[:]); n != 0 || err == nil || httpProxyTimedOut(err) {
			t.Fatal("over-limit source was not immediately rejected:", err)
		}
		_ = client.Close()
		select {
		case <-canceled:
		case <-time.After(4 * time.Second):
			t.Fatal("disconnect did not cancel a pending CONNECT dial")
		}
		closeCtx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		if err := h.Close(closeCtx); err != nil || len(h.ActiveSessions()) != 0 || h.Stats().Sessions != 0 {
			t.Fatal("pending connection leaked runtime state:", err)
		}
		lease, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal("listener remained owned after shutdown:", err)
		}
		_ = lease.Close()
	})
}
