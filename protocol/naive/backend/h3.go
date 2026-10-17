//go:build with_quic

package backend

import (
	"context"
	"crypto/tls"
	"errors"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func H3Enabled() bool { return true }

type h3Connection struct {
	client    *http3.ClientConn
	quic      *quic.Conn
	transport *quic.Transport
	packet    net.PacketConn
	ctx       context.Context
	config    ClientConfig
}

func newH3Connection(ctx, lifetime context.Context, config ClientConfig) (connection, error) {
	if config.PacketSocket == nil {
		return nil, ErrProtocol
	}
	packet, remote, err := config.PacketSocket(ctx)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packet}
	tc := config.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{http3.NextProtoH3}
	qc := &quic.Config{HandshakeIdleTimeout: config.ConnectTimeout, MaxIdleTimeout: config.IdleTimeout,
		InitialStreamReceiveWindow: 1 << 20, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 4 << 20, MaxConnectionReceiveWindow: 32 << 20}
	conn, err := transport.Dial(ctx, remote, tc, qc)
	if err != nil {
		_ = transport.Close()
		_ = packet.Close()
		return nil, err
	}
	httpTransport := &http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: MaxHeaders}
	return &h3Connection{client: httpTransport.NewClientConn(conn), quic: conn, transport: transport, packet: packet, ctx: lifetime, config: config}, nil
}
func (h *h3Connection) alive() bool { return h.quic.Context().Err() == nil }
func (h *h3Connection) close() error {
	_ = h.quic.CloseWithError(0, "")
	_ = h.transport.Close()
	return h.packet.Close()
}
func (h *h3Connection) open(ctx context.Context, authority string, headers http.Header) (net.Conn, bool, error) {
	stream, err := h.client.OpenRequestStream(ctx)
	if err != nil {
		return nil, false, err
	}
	cancelStream := func() {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
	}
	stop := untilEstablished(ctx, cancelStream)
	defer stop()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: authority}, Host: authority, Header: headers, ContentLength: -1}
	if err = stream.SendRequestHeader(req); err != nil {
		cancelStream()
		return nil, false, err
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		cancelStream()
		return nil, false, err
	}
	padding, err := paddingOffered(resp.Header)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || ctx.Err() != nil {
		cancelStream()
		return nil, false, ErrProtocol
	}
	stop()
	conn := newBodyConn(io.NopCloser(stream), stream, stream.Close, func(graceful bool) {
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if !graceful {
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
	}, h.quic.LocalAddr(), h.quic.RemoteAddr(), h.config.IdleTimeout)
	return conn, padding, nil
}

type h3Server struct{ server *http3.Server }

type h3ConnectionContextKey struct{}

func h3TunnelContext(req *http.Request) context.Context {
	if ctx, ok := req.Context().Value(h3ConnectionContextKey{}).(context.Context); ok {
		return ctx
	}
	return req.Context()
}

func newH3Server(tlsConfig *tls.Config, handler http.Handler, maxStreams int, timeout time.Duration) http3Server {
	return &h3Server{server: &http3.Server{TLSConfig: http3.ConfigureTLSConfig(tlsConfig), Handler: handler,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			return context.WithValue(ctx, h3ConnectionContextKey{}, ctx)
		},
		MaxHeaderBytes: MaxHeaders, IdleTimeout: timeout, QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIncomingStreams: int64(maxStreams),
			MaxIdleTimeout: timeout, InitialStreamReceiveWindow: 1 << 20, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 4 << 20, MaxConnectionReceiveWindow: 32 << 20}}}
}
func (s *h3Server) serve(packet net.PacketConn) error { return s.server.Serve(packet) }
func (s *h3Server) close() error                      { return s.server.Close() }
func takeH3Stream(w http.ResponseWriter, req *http.Request, idle time.Duration, cancelTunnel context.CancelFunc) (net.Conn, bool) {
	owner, ok := w.(http3.HTTPStreamer)
	if !ok {
		return nil, false
	}
	stream := owner.HTTPStream()
	sendStopped := make(chan struct{})
	stopSend := context.AfterFunc(stream.Context(), func() {
		defer close(sendStopped)
		// A local normal FIN has context.Canceled as its cause. STOP_SENDING
		// and reset/connection failures carry a stream/connection error instead.
		if !errors.Is(context.Cause(stream.Context()), context.Canceled) {
			cancelTunnel()
		}
	})
	closeStream := func(graceful bool) {
		if !stopSend() {
			<-sendStopped
		}
		// bodyConn termination (including its existing idle timer) is a
		// whole-tunnel event even if one relay worker already completed EOF.
		cancelTunnel()
		stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		if !graceful {
			stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestCanceled))
		}
	}
	conn := newBodyConn(io.NopCloser(stream), stream, stream.Close, closeStream, streamAddr("naive-server"), streamAddr(req.RemoteAddr), idle)
	return conn, true
}
