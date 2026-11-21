package native

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
)

type HTTPCompiler struct{}

func (HTTPCompiler) ProtocolID() string { return "http" }

func (HTTPCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := proxy.HTTPInbound().BuildRuntime(context.Background(), in)
	return err
}

func (c HTTPCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	owner, err := newManagedProxyHandle(ctx, in, "HTTP proxy", managedProxyLimits{
		connections: 512, handshakes: 64, perSource: 8,
	})
	if err != nil {
		return nil, err
	}
	h := &httpProxyHandle{
		managedProxyHandle: owner, headerTimeout: 10 * time.Second,
		connectTimeout: 10 * time.Second, idleTimeout: 60 * time.Second,
		sessions: make(map[identity.ID]ports.InboundSession),
	}
	owner.serve = h.serve
	return h, nil
}

type httpProxyHandle struct {
	*managedProxyHandle
	headerTimeout, connectTimeout, idleTimeout time.Duration
	sessions                                   map[identity.ID]ports.InboundSession // guarded by mu
}

func (h *httpProxyHandle) ActiveSessions() []ports.InboundSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	active := make([]ports.InboundSession, 0, len(h.sessions))
	for _, session := range h.sessions {
		active = append(active, session)
	}
	slices.SortFunc(active, func(a, b ports.InboundSession) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return active
}

func (h *httpProxyHandle) track(user *managedProxyUser, mode string) (func(), error) {
	id, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, net.ErrClosed
	}
	h.sessions[id] = ports.InboundSession{ID: id, BindingID: user.binding.ID, Mode: mode, StartedAt: time.Now().UTC()}
	return func() {
		h.mu.Lock()
		delete(h.sessions, id)
		h.mu.Unlock()
	}, nil
}

func (h *httpProxyHandle) dialTarget(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	ctx = ports.WithDirectServerTarget(ctx, func(resolved access.Endpoint) error {
		if h.ownsDestination(resolved) {
			return errProxySelfTarget
		}
		return nil
	})
	return h.managedProxyHandle.dialTarget(ctx, target)
}

func (h *httpProxyHandle) serve(raw net.Conn, finishHandshake func()) {
	authCtx, cancelAuth := context.WithTimeout(h.ctx, h.headerTimeout)
	defer cancelAuth()
	deadline, _ := authCtx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return
	}
	local := &httpProxyConn{Conn: raw, reader: raw}
	req, reader, err := httpproxy.ReadRequest(bufio.NewReader(local))
	if err != nil {
		status := http.StatusBadRequest
		if httpProxyTimedOut(err) {
			status = http.StatusRequestTimeout
		}
		h.reject(raw, status)
		return
	}
	// Closing the socket before Body.Close prevents draining a rejected upload.
	defer func() { _ = raw.Close(); _ = req.Body.Close() }()
	pair, err := httpproxy.Basic(req.Header.Get("Proxy-Authorization"))
	var user *managedProxyUser
	if err == nil {
		user = h.authenticate(authCtx, pair.Username, pair.Password)
	}
	cancelAuth()
	if user == nil {
		h.reject(raw, http.StatusProxyAuthRequired)
		return
	}
	target, err := httpproxy.Target(req)
	if err != nil {
		h.reject(raw, http.StatusBadRequest)
		return
	}
	if req.Header.Get("Upgrade") != "" || headerHasToken(req.Header, "Connection", "upgrade") {
		h.reject(raw, http.StatusNotImplemented)
		return
	}
	expect := req.Header.Values("Expect")
	if len(expect) != 0 && (len(expect) != 1 || !strings.EqualFold(expect[0], "100-continue") || req.Method == http.MethodConnect) {
		h.reject(raw, http.StatusExpectationFailed)
		return
	}
	if raw.SetDeadline(time.Time{}) != nil {
		return
	}
	if req.Method == http.MethodConnect {
		h.tunnel(raw, reader, target, user, finishHandshake)
		return
	}
	// All future reads through reader and the parsed body use the idle budget.
	local.idle = h.idleTimeout
	h.forward(local, reader, req, target, user, finishHandshake)
}

func (h *httpProxyHandle) reject(conn net.Conn, status int) {
	_ = conn.SetWriteDeadline(time.Now().Add(h.headerTimeout))
	challenge := ""
	if status == http.StatusProxyAuthRequired {
		challenge = "Proxy-Authenticate: Basic realm=\"Splicore\"\r\n"
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n%sConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status), challenge)
}

func httpProxyTimedOut(err error) bool {
	var timed net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timed) && timed.Timeout()
}

func proxyDialStatus(err error) int {
	switch {
	case errors.Is(err, errProxySelfTarget):
		return http.StatusForbidden
	case httpProxyTimedOut(err):
		return http.StatusGatewayTimeout
	default:
		return http.StatusBadGateway
	}
}

func headerHasToken(header http.Header, field, token string) bool {
	for _, value := range header.Values(field) {
		for item := range strings.SplitSeq(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}

func (h *httpProxyHandle) tunnel(local net.Conn, reader *bufio.Reader, target access.Endpoint, user *managedProxyUser, finishHandshake func()) {
	ctx, cancel := context.WithTimeout(h.ctx, h.connectTimeout)
	defer cancel()
	// A peek detects disconnect during a pending dial without consuming any
	// coalesced tunnel bytes. Wake and join it before handing the reader over.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := reader.Peek(1); err != nil && !httpProxyTimedOut(err) {
			cancel()
		}
	}()
	remote, err := h.dialTarget(ctx, target)
	_ = local.SetReadDeadline(time.Now())
	<-done
	canceled := ctx.Err()
	cancel()
	if err != nil {
		h.reject(local, proxyDialStatus(err))
		return
	}
	defer remote.Close()
	if canceled != nil {
		return
	}

	untrack, err := h.track(user, "connect")
	if err != nil {
		h.reject(local, http.StatusServiceUnavailable)
		return
	}
	defer untrack()
	_ = local.SetWriteDeadline(time.Now().Add(h.headerTimeout))
	if _, err := io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	finishHandshake()
	var activity sync.Mutex
	touch := func() {
		activity.Lock()
		defer activity.Unlock()
		deadline := time.Now().Add(h.idleTimeout)
		_ = local.SetDeadline(deadline)
		_ = remote.SetDeadline(deadline)
	}
	touch()
	in := &httpProxyConn{Conn: local, reader: reader, touch: touch}
	out := &httpProxyConn{Conn: remote, reader: remote, touch: touch}
	relay.Join(h.ctx, traffic.Conn(in, &h.total, user.stats), out)
}

// Forward a single request and advertise closure. After the framed upload,
// watch the client for disconnect without draining or forwarding a second
// request; earlier cancellation also wakes an in-flight protected dial.
func (h *httpProxyHandle) forward(local net.Conn, reader *bufio.Reader, req *http.Request, target access.Endpoint, user *managedProxyUser, finishHandshake func()) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	out := httpproxy.ForwardRequest(req)
	out.RequestURI, out.Close = "", true
	out.Header.Del("Expect")
	uploadDone, watchDone := make(chan struct{}), make(chan struct{})
	counters := []*traffic.Counter{&h.total, user.stats}
	upload := &httpProxyBody{
		ReadCloser: out.Body, complete: sync.OnceFunc(func() { close(uploadDone) }),
		count: func(n int) { traffic.CountUpload(n, counters...) },
	}
	if out.Body == http.NoBody {
		upload.complete()
	} else {
		out.Body = upload
	}
	go func() {
		defer close(watchDone)
		select {
		case <-uploadDone:
		case <-ctx.Done():
			return
		}
		if _, err := reader.Peek(1); err != nil {
			cancel()
		}
	}()
	defer func() { cancel(); _ = local.Close(); <-watchDone }()

	dialCtx, finishDial := context.WithTimeout(ctx, h.connectTimeout)
	remote, err := h.dialTarget(dialCtx, target)
	finishDial()
	if err != nil {
		h.reject(local, proxyDialStatus(err))
		return
	}
	defer remote.Close()
	untrack, err := h.track(user, "forward")
	if err != nil {
		h.reject(local, http.StatusServiceUnavailable)
		return
	}
	defer untrack()
	finishHandshake()
	release := traffic.Open(true, counters...)
	defer release()
	if len(req.Header.Values("Expect")) != 0 && out.Body != http.NoBody {
		if _, err := io.WriteString(local, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return
		}
	}

	var claimed atomic.Bool
	transport := &http.Transport{
		DisableCompression: true, DisableKeepAlives: true,
		ResponseHeaderTimeout: h.headerTimeout, MaxResponseHeaderBytes: httpproxy.MaxHeader,
		DialContext: func(call context.Context, _, _ string) (net.Conn, error) {
			if ctx.Err() != nil || call.Err() != nil || !claimed.CompareAndSwap(false, true) {
				return nil, net.ErrClosed
			}
			return httpproxy.NewResponseHeaderConn(&httpProxyConn{Conn: remote, reader: remote, idle: h.idleTimeout}), nil
		},
	}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(out.WithContext(ctx))
	if err != nil {
		status := int(upload.failure.Load())
		if status == 0 {
			status = proxyDialStatus(err)
		}
		h.reject(local, status)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.reject(local, http.StatusBadGateway)
		return
	}
	response := httpproxy.ForwardResponse(resp)
	if response.Body != http.NoBody {
		response.Body = &httpProxyBody{ReadCloser: response.Body, count: func(n int) { traffic.CountDownload(n, counters...) }}
	}
	_ = response.Write(local)
}

// The socket owner closes the incoming parser body after interrupting the read.
// Transport may call Close while its write loop is still unwinding.
type httpProxyBody struct {
	io.ReadCloser
	count    func(int)
	complete func()
	failure  atomic.Int32
}

func (b *httpProxyBody) Close() error { return nil }

func (b *httpProxyBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count(n)
	if b.complete != nil {
		switch {
		case err == io.EOF:
			b.complete()
		case httpProxyTimedOut(err):
			b.failure.Store(http.StatusRequestTimeout)
		case err != nil:
			b.failure.Store(http.StatusBadRequest)
		}
	}
	return n, err
}

type httpProxyConn struct {
	net.Conn
	reader io.Reader
	idle   time.Duration
	touch  func()
}

func (c *httpProxyConn) Read(p []byte) (int, error) {
	if c.idle != 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.idle))
	}
	n, err := c.reader.Read(p)
	if n > 0 && c.touch != nil {
		c.touch()
	}
	return n, err
}

func (c *httpProxyConn) Write(p []byte) (int, error) {
	if c.idle != 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.idle))
	}
	n, err := c.Conn.Write(p)
	if n > 0 && c.touch != nil {
		c.touch()
	}
	return n, err
}

func (c *httpProxyConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return errors.ErrUnsupported
}
