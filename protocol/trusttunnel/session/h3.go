//go:build with_quic

package session

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func H3Enabled() bool { return true }
func classifyH3(c Code, err error) Code {
	var app *quic.ApplicationError
	var stream *quic.StreamError
	var transport *quic.TransportError
	if errors.As(err, &app) && app.ErrorCode == 0x1f || errors.As(err, &stream) && stream.ErrorCode == 0x1f {
		return Auth
	}
	if errors.As(err, &transport) && transport.ErrorCode == 0x178 {
		return ALPN
	}
	return c
}

type h3Connection struct {
	client    *http3.ClientConn
	q         *quic.Conn
	transport *quic.Transport
	packet    net.PacketConn
	idle      time.Duration
}

func newH3(ctx, lifetime context.Context, c ClientConfig, address string) (connection, error) {
	packet, remote, e := c.PacketSocket(ctx, address)
	if e != nil {
		return nil, classify(QUIC, e)
	}
	tr := &quic.Transport{Conn: packet}
	tc := c.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{http3.NextProtoH3}
	q, e := tr.Dial(ctx, remote, tc, &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: c.ConnectTimeout, MaxIdleTimeout: 2 * (c.ConnectTimeout + c.HealthTimeout), InitialStreamReceiveWindow: 131072, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 16 << 20})
	if e != nil {
		_ = tr.Close()
		_ = packet.Close()
		return nil, classify(QUIC, e)
	}
	ht := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: maxHeaders}
	return &h3Connection{ht.NewClientConn(q), q, tr, packet, c.StreamIdleTimeout}, nil
}
func (h *h3Connection) alive() bool { return h.q.Context().Err() == nil }
func (h *h3Connection) close() error {
	_ = h.q.CloseWithError(0, "")
	_ = h.transport.Close()
	return h.packet.Close()
}
func (h *h3Connection) open(ctx context.Context, authority string, headers http.Header) (net.Conn, error) {
	s, e := h.client.OpenRequestStream(ctx)
	if e != nil {
		return nil, classify(HTTP, e)
	}
	cancel := func() {
		s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	stop := untilEstablished(ctx, cancel)
	defer stop()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: authority}, Host: authority, Header: headers, ContentLength: -1}
	if e = s.SendRequestHeader(req); e != nil {
		cancel()
		return nil, classify(HTTP, e)
	}
	resp, e := s.ReadResponse()
	if e != nil {
		cancel()
		if ctx.Err() != nil {
			return nil, failure(Closed, ctx.Err())
		}
		return nil, classify(HTTP, e)
	}
	if resp.StatusCode != 200 || ctx.Err() != nil {
		cancel()
		if ctx.Err() != nil {
			return nil, failure(Closed, ctx.Err())
		}
		return nil, status(resp.StatusCode)
	}
	stop()
	conn := newBodyConn(io.NopCloser(s), s, s.Close, func(graceful bool) {
		s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if !graceful {
			s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
	}, h.q.LocalAddr(), h.q.RemoteAddr(), h.idle)
	// This experimental compatibility sequence completes isolated official
	// request-EOF controls, but the full official campaign still has response
	// EOF failures. Empty DATA is not EOF: RequestStream.Close supplies FIN.
	// Queue this write through bodyConn so flow control cannot bypass deadlines
	// or prevent full Close from interrupting send-half completion.
	conn.prepareCloseWrite = func() error { _, err := s.Write(nil); return err }
	return conn, nil
}

type h3Server struct{ s *http3.Server }

func newH3Server(c ServerConfig, h http.Handler, onSession func(context.Context, func()) context.Context) *h3Server {
	return &h3Server{&http3.Server{TLSConfig: http3.ConfigureTLSConfig(c.TLS), Handler: h, MaxHeaderBytes: maxHeaders, IdleTimeout: c.IdleTimeout, ConnContext: func(ctx context.Context, q *quic.Conn) context.Context {
		return onSession(ctx, func() { _ = q.CloseWithError(0x1f, "") })
	}, QUICConfig: &quic.Config{Versions: []quic.Version{quic.Version1}, MaxIncomingStreams: int64(c.MaxStreams), HandshakeIdleTimeout: c.ConnectTimeout, MaxIdleTimeout: c.IdleTimeout, InitialStreamReceiveWindow: 131072, MaxStreamReceiveWindow: 1 << 20, InitialConnectionReceiveWindow: 8 << 20, MaxConnectionReceiveWindow: 16 << 20}}}
}
func (h *h3Server) serve(p net.PacketConn) error { return h.s.Serve(p) }
func (h *h3Server) close() error                 { return h.s.Close() }
func takeH3(w http.ResponseWriter, r *http.Request, idle time.Duration, cancel context.CancelFunc) (net.Conn, bool) {
	owner, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, false
	}
	s := owner.HTTPStream()
	stopped := make(chan struct{})
	stop := context.AfterFunc(s.Context(), func() {
		defer close(stopped)
		if !errors.Is(context.Cause(s.Context()), context.Canceled) {
			cancel()
		}
	})
	return newBodyConn(io.NopCloser(s), s, s.Close, func(graceful bool) {
		if !stop() {
			<-stopped
		}
		cancel()
		s.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if !graceful {
			s.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
	}, streamAddr("trusttunnel-server"), streamAddr(r.RemoteAddr), idle), true
}
