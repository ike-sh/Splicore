package session

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const maxHeaders = 32 << 10

type connection interface {
	open(context.Context, string, http.Header) (net.Conn, error)
	alive() bool
	close() error
}
type h2Connection struct {
	client *http2.ClientConn
	tcp    net.Conn
	ctx    context.Context
	idle   time.Duration
}

func newH2(ctx, lifetime context.Context, c ClientConfig, address string) (connection, error) {
	raw, e := c.DialTCP(ctx, "tcp", address)
	if e != nil {
		return nil, classify(TCP, e)
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = raw.Close(); close(stopped) })
	var once sync.Once
	finish := func() {
		once.Do(func() {
			if !stop() {
				<-stopped
			}
		})
	}
	defer finish()
	if d, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(d)
	}
	tc := c.TLS.Clone()
	tc.NextProtos = []string{"h2"}
	conn := tls.Client(raw, tc)
	if e = conn.HandshakeContext(ctx); e != nil {
		_ = raw.Close()
		return nil, classify(TLS, e)
	}
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, failure(ALPN, nil)
	}
	// ConfigureTransports attaches net/http.HTTP2Config to x/net's transport.
	// NewClientConn then emits SETTINGS_INITIAL_WINDOW_SIZE=131072 on the wire.
	h1 := &http.Transport{HTTP2: &http.HTTP2Config{MaxReceiveBufferPerStream: 131072, MaxReceiveBufferPerConnection: 8 << 20}}
	tr, e := http2.ConfigureTransports(h1)
	if e != nil {
		_ = conn.Close()
		return nil, classify(HTTP, e)
	}
	tr.DisableCompression = true
	tr.StrictMaxConcurrentStreams = true
	tr.MaxHeaderListSize = maxHeaders
	cc, e := tr.NewClientConn(conn)
	if e != nil {
		_ = conn.Close()
		return nil, classify(HTTP, e)
	}
	finish()
	if ctx.Err() != nil {
		_ = cc.Close()
		return nil, failure(Closed, ctx.Err())
	}
	if e = raw.SetDeadline(time.Time{}); e != nil {
		_ = cc.Close()
		return nil, failure(TCP, e)
	}
	return &h2Connection{cc, conn, lifetime, c.StreamIdleTimeout}, nil
}
func (h *h2Connection) alive() bool  { s := h.client.State(); return !s.Closed && !s.Closing }
func (h *h2Connection) close() error { _ = h.client.Close(); return h.tcp.Close() }
func (h *h2Connection) open(ctx context.Context, authority string, headers http.Header) (net.Conn, error) {
	sc, cancel := context.WithCancel(h.ctx)
	stop := untilEstablished(ctx, cancel)
	defer stop()
	r, w := io.Pipe()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: authority}, Host: authority, Header: headers, Body: r, ContentLength: -1}
	resp, e := h.client.RoundTrip(req.WithContext(sc))
	if e != nil {
		cancel()
		_ = r.Close()
		_ = w.Close()
		if ctx.Err() != nil {
			return nil, failure(Closed, ctx.Err())
		}
		return nil, classify(HTTP, e)
	}
	if resp.StatusCode != 200 || ctx.Err() != nil {
		cancel()
		_ = resp.Body.Close()
		_ = r.Close()
		_ = w.Close()
		if ctx.Err() != nil {
			return nil, failure(Closed, ctx.Err())
		}
		return nil, status(resp.StatusCode)
	}
	stop()
	return newBodyConn(resp.Body, w, w.Close, func(bool) { cancel(); _ = r.Close() }, h.tcp.LocalAddr(), h.tcp.RemoteAddr(), h.idle), nil
}
