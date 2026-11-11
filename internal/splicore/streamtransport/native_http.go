package streamtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/net/http2"
)

var errNativeConfig = errors.New("invalid native stream transport configuration")

const nativeContentType = "application/octet-stream"

// httpBodyConn uses bounded standard HTTP flow control directly, without a
// payload queue. A deadline is terminal because a partial HTTP write cannot be
// rolled back safely. It never changes deadlines on a sibling H2 stream.
type httpBodyConn struct {
	readGeneration, writeGeneration uint64
	calls                           sync.WaitGroup
	reader                          io.ReadCloser
	writer                          io.Writer
	closeWrite                      func() error
	abort                           func()
	local, remote                   net.Addr
	done, readDone, writeDone       chan struct{}
	once, readOnce, writeOnce       sync.Once
	mu                              sync.Mutex
	writeMu                         sync.Mutex
	readTimer, writeTimer           *time.Timer
	expired                         atomic.Bool
}

func newHTTPBody(r io.ReadCloser, w io.Writer, half func() error, abort func(), local, remote net.Addr) *httpBodyConn {
	return &httpBodyConn{reader: r, writer: w, closeWrite: half, abort: abort, local: local, remote: remote, done: make(chan struct{}), readDone: make(chan struct{}), writeDone: make(chan struct{})}
}

func (c *httpBodyConn) Read(p []byte) (int, error) {
	if !c.beginIO() {
		return 0, net.ErrClosed
	}
	defer c.calls.Done()
	if len(p) == 0 {
		return 0, nil
	}
	n, e := c.reader.Read(p)
	if e == io.EOF {
		c.readOnce.Do(func() { close(c.readDone) })
	}
	if e != nil && c.expired.Load() {
		e = os.ErrDeadlineExceeded
	}
	return n, e
}

func (c *httpBodyConn) Write(p []byte) (int, error) {
	// Keep the complete writer operation (server Write + Flush) atomic per
	// logical stream. Reads and shutdown do not acquire this lock.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if !c.beginIO() {
		return 0, net.ErrClosed
	}
	defer c.calls.Done()
	select {
	case <-c.done:
		return 0, net.ErrClosed
	case <-c.writeDone:
		return 0, io.ErrClosedPipe
	default:
	}
	n, e := c.writer.Write(p)
	if e != nil && c.expired.Load() {
		e = os.ErrDeadlineExceeded
	}
	return n, e
}

func (c *httpBodyConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	var e error
	c.writeOnce.Do(func() { e = c.closeWrite(); close(c.writeDone) })
	return e
}
func (c *httpBodyConn) Close() error { return c.shutdown(true) }
func (c *httpBodyConn) shutdown(abort bool) error {
	c.once.Do(func() {
		c.mu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		close(c.done)
		c.mu.Unlock()
		if abort {
			c.abort()
		}
	})
	return nil
}
func (c *httpBodyConn) LocalAddr() net.Addr  { return c.local }
func (c *httpBodyConn) RemoteAddr() net.Addr { return c.remote }
func (c *httpBodyConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *httpBodyConn) SetReadDeadline(t time.Time) error  { return c.setTimer(t, true) }
func (c *httpBodyConn) SetWriteDeadline(t time.Time) error { return c.setTimer(t, false) }
func (c *httpBodyConn) setTimer(at time.Time, read bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	timer := &c.writeTimer
	generation := &c.writeGeneration
	if read {
		timer = &c.readTimer
		generation = &c.readGeneration
	}
	*generation++
	current := *generation
	if *timer != nil {
		(*timer).Stop()
	}
	if !at.IsZero() {
		*timer = time.AfterFunc(time.Until(at), func() {
			c.mu.Lock()
			valid := *generation == current
			select {
			case <-c.done:
				valid = false
			default:
			}
			if valid {
				c.expired.Store(true)
			}
			c.mu.Unlock()
			if valid {
				c.Close()
			}
		})
	}
	return nil
}

type httpNativeClient struct {
	workers sync.WaitGroup
	cfg     cfg.Config
	target  string
	tls     *tls.Config
	dial    DialFunc
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	dialMu  sync.Mutex
	streams map[*httpBodyConn]bool
	sockets map[net.Conn]bool
	pending int
	h1      *http.Transport
	h2      *http2.ClientConn
	once    sync.Once
}

func nativeTLS(tc *tls.Config, c cfg.Config) (*tls.Config, error) {
	if tc == nil || c.Validate() != nil || c.ValidateALPN(tc.NextProtos) != nil {
		return nil, errNativeConfig
	}
	tc = tc.Clone()
	tc.NextProtos = []string{"http/1.1"}
	if c.Type() == "h2" {
		tc.NextProtos = []string{"h2"}
	}
	return tc, nil
}

func newHTTPClient(dial DialFunc, target string, c cfg.Config, tc *tls.Config) (*httpNativeClient, error) {
	tc, e := nativeTLS(tc, c)
	if e != nil || dial == nil || tc.ServerName == "" || c.Type() != "http" && c.Type() != "h2" {
		return nil, errNativeConfig
	}
	if _, _, e = net.SplitHostPort(target); e != nil {
		return nil, errNativeConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	cl := &httpNativeClient{cfg: c.Clone(), target: target, tls: tc, dial: dial, ctx: ctx, cancel: cancel, streams: map[*httpBodyConn]bool{}, sockets: map[net.Conn]bool{}}
	cl.h1 = &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: cfg.MaxHeaders, ResponseHeaderTimeout: HandshakeTimeout, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}, DialTLSContext: cl.connect}
	return cl, nil
}

func (c *httpNativeClient) connect(ctx context.Context, _, _ string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	ownerStop := context.AfterFunc(c.ctx, cancel)
	defer ownerStop()
	raw, e := c.dial(ctx, "tcp", c.target)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	secured := tls.Client(raw, c.tls)
	if e = secured.HandshakeContext(ctx); e != nil {
		raw.Close()
		return nil, e
	}
	if secured.ConnectionState().NegotiatedProtocol != c.tls.NextProtos[0] {
		raw.Close()
		return nil, errNativeConfig
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		raw.Close()
		return nil, net.ErrClosed
	}
	// The caller removes each dedicated H1 socket when its stream closes. The
	// single H2 carrier remains owned until eviction or outbound Close.
	wrapped := &httpClientSocket{Conn: secured, owner: c}
	c.sockets[wrapped] = true
	return wrapped, nil
}

func (c *httpNativeClient) h2Connection(ctx context.Context) (*http2.ClientConn, error) {
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	c.mu.Lock()
	cc := c.h2
	if cc != nil && cc.CanTakeNewRequest() {
		c.mu.Unlock()
		return cc, nil
	}
	if cc != nil && len(c.streams) > 0 {
		c.mu.Unlock()
		return nil, errors.New("HTTP/2 session draining")
	}
	c.h2 = nil
	old := make([]net.Conn, 0, len(c.sockets))
	if cc != nil {
		for raw := range c.sockets {
			old = append(old, raw)
		}
	}
	c.mu.Unlock()
	if cc != nil {
		cc.Close()
	}
	for _, raw := range old {
		raw.Close()
	}
	raw, e := c.connect(ctx, "tcp", c.target)
	if e != nil {
		return nil, e
	}
	tr := &http2.Transport{DisableCompression: true, StrictMaxConcurrentStreams: true, IdleConnTimeout: 30 * time.Second, MaxHeaderListSize: cfg.MaxHeaders}
	fresh, e := tr.NewClientConn(raw)
	if e != nil {
		raw.Close()
		c.mu.Lock()
		delete(c.sockets, raw)
		c.mu.Unlock()
		return nil, e
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		fresh.Close()
		return nil, net.ErrClosed
	}
	c.h2 = fresh
	c.mu.Unlock()
	return fresh, nil
}

func (c *httpNativeClient) DialContext(ctx context.Context) (net.Conn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.mu.Lock()
	if c.ctx.Err() != nil || c.pending+len(c.streams) >= 128 {
		c.mu.Unlock()
		return nil, errors.New("HTTP transport closed or stream limit reached")
	}
	c.pending++
	c.workers.Add(1)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.pending--; c.mu.Unlock(); c.workers.Done() }()
	requestCtx, cancel := context.WithCancel(c.ctx)
	stop := context.AfterFunc(ctx, cancel)
	timer := time.AfterFunc(HandshakeTimeout, cancel)
	defer stop()
	defer timer.Stop()
	reader, writer := io.Pipe()
	u, _ := url.Parse("https://" + c.target + c.cfg.HTTPPath())
	req := (&http.Request{Method: http.MethodPost, URL: u, Host: c.target, Header: make(http.Header), Body: reader, ContentLength: -1}).WithContext(requestCtx)
	if c.cfg.Host != "" {
		req.Host = c.cfg.Host
	}
	for k, v := range c.cfg.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", nativeContentType)
	var resp *http.Response
	var e error
	if c.cfg.Type() == "h2" {
		var cc *http2.ClientConn
		cc, e = c.h2Connection(requestCtx)
		if e == nil {
			resp, e = cc.RoundTrip(req)
		}
	} else {
		resp, e = c.h1.RoundTrip(req)
	}
	if e != nil {
		cancel()
		writer.CloseWithError(e)
		reader.Close()
		return nil, e
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != nativeContentType || resp.ProtoMajor != map[bool]int{false: 1, true: 2}[c.cfg.Type() == "h2"] || resp.Header.Get("Content-Encoding") != "" {
		cancel()
		writer.Close()
		reader.Close()
		resp.Body.Close()
		return nil, errors.New("HTTP transport rejected")
	}
	if !timer.Stop() || ctx.Err() != nil || requestCtx.Err() != nil {
		cancel()
		writer.Close()
		reader.Close()
		resp.Body.Close()
		return nil, context.Canceled
	}
	stop()
	var stream *httpBodyConn
	stream = newHTTPBody(resp.Body, writer, writer.Close, func() {
		cancel()
		writer.CloseWithError(net.ErrClosed)
		reader.Close()
		resp.Body.Close()
		c.mu.Lock()
		delete(c.streams, stream)
		c.mu.Unlock()
	}, transportAddr("http-local"), transportAddr(c.target))
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		stream.Close()
		return nil, net.ErrClosed
	}
	c.streams[stream] = true
	c.mu.Unlock()
	return stream, nil
}

func (c *httpNativeClient) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		streams := make([]*httpBodyConn, 0, len(c.streams))
		for s := range c.streams {
			streams = append(streams, s)
		}
		sockets := make([]net.Conn, 0, len(c.sockets))
		for raw := range c.sockets {
			sockets = append(sockets, raw)
		}
		cc := c.h2
		c.mu.Unlock()
		for _, raw := range sockets {
			raw.Close()
		}
		for _, s := range streams {
			s.Close()
		}
		if cc != nil {
			cc.Close()
		}
		c.h1.CloseIdleConnections()
		c.workers.Wait()
	})
	return nil
}

// A server handler retains its ResponseWriter and request body until the stream
// owner closes or both directions reach EOF. CloseWrite never terminates input.
type httpNativeListener struct {
	slots    chan struct{}
	base     net.Listener
	server   *http.Server
	ctx      context.Context
	cancel   context.CancelFunc
	queue    chan net.Conn
	mu       sync.Mutex
	sockets  map[net.Conn]bool
	streams  map[*httpBodyConn]bool
	handlers sync.WaitGroup
	serve    sync.WaitGroup
	once     sync.Once
}
type flushBody struct {
	w          http.ResponseWriter
	controller *http.ResponseController
}

func (w flushBody) Write(p []byte) (int, error) {
	n, e := w.w.Write(p)
	if e == nil {
		e = w.controller.Flush()
	}
	return n, e
}

func nativeRequestStatus(r *http.Request, c cfg.Config) int {
	if r.RequestURI != c.HTTPPath() || r.URL.IsAbs() || r.URL.RawQuery != "" {
		return http.StatusNotFound
	}
	if r.Method != http.MethodPost {
		return http.StatusMethodNotAllowed
	}
	want := 1
	if c.Type() == "h2" {
		want = 2
	}
	if r.ProtoMajor != want || want == 1 && r.ProtoMinor != 1 || c.Host != "" && !strings.EqualFold(r.Host, c.Host) {
		return http.StatusBadRequest
	}
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != nativeContentType || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Expect") != "" || r.Header.Get("Upgrade") != "" || r.ContentLength >= 0 || len(r.Trailer) != 0 {
		return http.StatusBadRequest
	}
	size := len(r.RequestURI) + len(r.Host)
	for k, vs := range r.Header {
		for _, v := range vs {
			size += len(k) + len(v) + 4
		}
	}
	if size > cfg.MaxHeaders {
		return http.StatusRequestHeaderFieldsTooLarge
	}
	return 0
}

func newHTTPListener(base net.Listener, c cfg.Config, tc *tls.Config) (net.Listener, error) {
	tc, e := nativeTLS(tc, c)
	if e != nil || base == nil || c.ValidateServer() != nil || len(tc.Certificates) == 0 && tc.GetCertificate == nil {
		return nil, errNativeConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &httpNativeListener{slots: make(chan struct{}, 512), base: base, ctx: ctx, cancel: cancel, queue: make(chan net.Conn, 64), sockets: map[net.Conn]bool{}, streams: map[*httpBodyConn]bool{}}
	l.server = &http.Server{TLSConfig: tc, ReadHeaderTimeout: HandshakeTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: cfg.MaxHeaders, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { l.handle(w, r, c) }), ErrorLog: quietHTTPLog()}
	if c.Type() == "h2" {
		if e = http2.ConfigureServer(l.server, &http2.Server{MaxConcurrentStreams: 128, IdleTimeout: 30 * time.Second, MaxReadFrameSize: 16 << 10, MaxUploadBufferPerStream: 256 << 10, MaxUploadBufferPerConnection: 2 << 20}); e != nil {
			cancel()
			return nil, e
		}
	} else {
		l.server.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	l.serve.Go(func() {
		defer l.cancel()
		_ = l.server.ServeTLS(&httpBoundListener{Listener: base, owner: l}, "", "")
	})
	return l, nil
}

func (l *httpNativeListener) handle(w http.ResponseWriter, r *http.Request, c cfg.Config) {
	if code := nativeRequestStatus(r, c); code != 0 {
		rejectNativeRequest(w, r, code)
		return
	}
	select {
	case l.slots <- struct{}{}:
		defer func() { <-l.slots }()
	default:
		rejectNativeRequest(w, r, http.StatusServiceUnavailable)
		return
	}
	l.mu.Lock()
	if l.ctx.Err() != nil {
		l.mu.Unlock()
		rejectNativeRequest(w, r, http.StatusServiceUnavailable)
		return
	}
	l.handlers.Add(1)
	l.mu.Unlock()
	defer l.handlers.Done()
	ctl := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if e := ctl.EnableFullDuplex(); e != nil {
			rejectNativeRequest(w, r, http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Connection", "close")
	}
	w.Header().Set("Content-Type", nativeContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if ctl.Flush() != nil {
		return
	}
	peer := transportAddr(r.RemoteAddr)
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	stream := newHTTPBody(r.Body, flushBody{w, ctl}, func() error { return nil }, func() { ctl.SetReadDeadline(time.Now()); ctl.SetWriteDeadline(time.Now()); r.Body.Close() }, local, peer)
	l.mu.Lock()
	if l.ctx.Err() != nil {
		l.mu.Unlock()
		stream.Close()
		return
	}
	l.streams[stream] = true
	l.mu.Unlock()
	graceful := false
	defer func() {
		stream.shutdown(!graceful)
		stream.calls.Wait()
		l.mu.Lock()
		delete(l.streams, stream)
		l.mu.Unlock()
	}()
	select {
	case l.queue <- stream:
	case <-l.ctx.Done():
		return
	default:
		return
	}
	select {
	case <-stream.done:
	case <-r.Context().Done():
	case <-l.ctx.Done():
	case <-stream.writeDone:
		select {
		case <-stream.readDone:
			graceful = true
		case <-stream.done:
		case <-r.Context().Done():
		case <-l.ctx.Done():
		}
	}
}

func (l *httpNativeListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	case c := <-l.queue:
		if l.ctx.Err() != nil {
			c.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	}
}
func (l *httpNativeListener) Addr() net.Addr { return l.base.Addr() }
func (l *httpNativeListener) Close() error {
	l.once.Do(func() {
		l.cancel()
		l.base.Close()
		l.server.Close()
		l.mu.Lock()
		ss := make([]*httpBodyConn, 0, len(l.streams))
		for s := range l.streams {
			ss = append(ss, s)
		}
		sockets := make([]net.Conn, 0, len(l.sockets))
		for raw := range l.sockets {
			sockets = append(sockets, raw)
		}
		l.mu.Unlock()
		for _, raw := range sockets {
			raw.Close()
		}
		for _, s := range ss {
			s.Close()
		}
		l.serve.Wait()
		l.handlers.Wait()
		for {
			select {
			case c := <-l.queue:
				c.Close()
			default:
				return
			}
		}
	})
	return nil
}

type httpBoundListener struct {
	net.Listener
	owner *httpNativeListener
}

func (l *httpBoundListener) Accept() (net.Conn, error) {
	for {
		raw, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		l.owner.mu.Lock()
		if l.owner.ctx.Err() != nil || len(l.owner.sockets) >= 512 {
			l.owner.mu.Unlock()
			raw.Close()
			continue
		}
		wrapped := &httpServerSocket{Conn: raw, owner: l.owner}
		l.owner.sockets[wrapped] = true
		l.owner.mu.Unlock()
		return wrapped, nil
	}
}

func quietHTTPLog() *log.Logger { return log.New(io.Discard, "", 0) }

type httpClientSocket struct {
	net.Conn
	owner *httpNativeClient
	once  sync.Once
}

func (c *httpClientSocket) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.sockets, c); c.owner.mu.Unlock() })
	return e
}

type httpServerSocket struct {
	net.Conn
	owner *httpNativeListener
	once  sync.Once
}

func (c *httpServerSocket) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.sockets, c); c.owner.mu.Unlock() })
	return e
}

func (c *httpBodyConn) beginIO() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return false
	default:
		c.calls.Add(1)
		return true
	}
}

// Rejected H1 requests must not retain a socket while net/http drains a slow
// unread request body. Flush the deterministic response, then expire its input.
func rejectNativeRequest(w http.ResponseWriter, r *http.Request, code int) {
	ctl := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		r.Close = true
		w.Header().Set("Connection", "close")
		ctl.SetWriteDeadline(time.Now().Add(HandshakeTimeout))
	}
	http.Error(w, http.StatusText(code), code)
	if r.ProtoMajor == 1 {
		_ = ctl.Flush()
		_ = ctl.SetReadDeadline(time.Now())
	}
}
