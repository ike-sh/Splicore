package streamtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/xhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type listener struct {
	raw         net.Listener
	http        *http.Server
	grpc        *grpc.Server
	ctx         context.Context
	cancel      context.CancelFunc
	queue       chan net.Conn
	mu          sync.Mutex
	connections map[net.Conn]bool
	streams     map[*grpcConn]bool
	once        sync.Once
	done        chan struct{}
	serve       sync.WaitGroup
	handlers    sync.WaitGroup
	watchers    sync.WaitGroup
}

// WrapListener takes ownership only on success. Raw TCP preserves the frozen
// protocol TLS path. HTTP and gRPC transports own their composed TLS handshake.
func WrapListener(base net.Listener, c cfg.Config, tc *tls.Config) (net.Listener, error) {
	if e := c.ValidateServer(); e != nil {
		return nil, e
	}
	if tc != nil {
		if e := c.ValidateALPN(tc.NextProtos); e != nil {
			return nil, e
		}
	}
	if c.Type() == "tcp" {
		return base, nil
	}
	if c.Type() == "mkcp" {
		if tc != nil {
			return tls.NewListener(base, tlsConfig(tc, "mkcp")), nil
		}
		return base, nil
	}
	if c.Type() == "xhttp" {
		return xhttp.NewListener(base, c, tc, nil)
	}
	if c.Type() != "ws" && c.Type() != "httpupgrade" && c.Type() != "grpc" {
		return nil, errors.New("unsupported stream listener")
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &listener{raw: base, ctx: ctx, cancel: cancel, queue: make(chan net.Conn, 64), connections: map[net.Conn]bool{}, streams: map[*grpcConn]bool{}, done: make(chan struct{})}
	if c.Type() == "grpc" {
		opts := []grpc.ServerOption{grpc.ForceServerCodec(hunkCodec{}), grpc.MaxRecvMsgSize(MaxMessage + 16), grpc.MaxSendMsgSize(MaxMessage + 16), grpc.MaxConcurrentStreams(128), grpc.MaxHeaderListSize(cfg.MaxHeaders), grpc.ConnectionTimeout(HandshakeTimeout)}
		if tc != nil {
			opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig(tc, "grpc"))))
		}
		l.grpc = grpc.NewServer(opts...)
		l.grpc.RegisterService(&grpc.ServiceDesc{ServiceName: c.Service(), HandlerType: (*any)(nil), Streams: []grpc.StreamDesc{{StreamName: "Tun", ClientStreams: true, ServerStreams: true, Handler: func(_ any, s grpc.ServerStream) error {
			if c.Host != "" {
				md, _ := metadata.FromIncomingContext(s.Context())
				a := md.Get(":authority")
				if len(a) != 1 || !strings.EqualFold(a[0], c.Host) {
					return status.Error(codes.PermissionDenied, "transport authority mismatch")
				}
			}
			if !l.begin() {
				return net.ErrClosed
			}
			defer l.handlers.Done()
			p, _ := peer.FromContext(s.Context())
			var addr net.Addr = transportAddr("grpc-peer")
			if p != nil {
				addr = p.Addr
			}
			stream := newGRPC(s.Context(), s, nil, nil, base.Addr(), addr)
			l.mu.Lock()
			l.streams[stream] = true
			l.mu.Unlock()
			l.watchers.Add(1)
			go func() {
				defer l.watchers.Done()
				<-stream.joined
				l.mu.Lock()
				delete(l.streams, stream)
				l.mu.Unlock()
			}()
			defer stream.Close()
			if !l.publish(stream) {
				return net.ErrClosed
			}
			select {
			case <-stream.ctx.Done():
				return nil
			case <-s.Context().Done():
				return s.Context().Err()
			case <-l.ctx.Done():
				return net.ErrClosed
			}
		}}}}, l)
		l.serve.Add(1)
		go func() {
			defer l.serve.Done()
			defer l.cancel()
			_ = l.grpc.Serve(&trackedListener{Listener: base, owner: l})
		}()
	} else {
		serving := base
		if tc != nil {
			serving = tls.NewListener(base, tlsConfig(tc, c.Type()))
		}
		l.http = &http.Server{ReadHeaderTimeout: HandshakeTimeout, IdleTimeout: HandshakeTimeout, MaxHeaderBytes: cfg.MaxHeaders, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.begin() {
				http.Error(w, "closed", 503)
				return
			}
			defer l.handlers.Done()
			if r.Method != "GET" || r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.RequestURI != c.HTTPPath() || c.Host != "" && !strings.EqualFold(r.Host, c.Host) || r.ContentLength != 0 || len(r.TransferEncoding) > 0 || r.Header.Get("Sec-WebSocket-Protocol") != "" {
				http.Error(w, "invalid transport request", 400)
				return
			}
			size := len(r.RequestURI) + len(r.Host)
			for k, vs := range r.Header {
				for _, v := range vs {
					size += len(k) + len(v) + 4
				}
			}
			if size > cfg.MaxHeaders {
				http.Error(w, "headers exceed bound", 431)
				return
			}
			if c.Type() == "ws" {
				u := websocket.Upgrader{ReadBufferSize: 4096, WriteBufferSize: ChunkSize, HandshakeTimeout: HandshakeTimeout, CheckOrigin: func(*http.Request) bool { return true }}
				ws, e := u.Upgrade(w, r, nil)
				if e != nil {
					return
				}
				stream := newWS(ws)
				if !l.publish(stream) {
					stream.Close()
				}
				return
			}
			if !token(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "upgrade required", 400)
				return
			}
			raw, rw, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			raw.SetWriteDeadline(time.Now().Add(HandshakeTimeout))
			_, e = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			if e == nil {
				e = rw.Flush()
			}
			if e != nil {
				raw.Close()
				return
			}
			raw.SetDeadline(time.Time{})
			stream := &bufferedConn{Conn: raw, reader: rw.Reader}
			if !l.publish(stream) {
				stream.Close()
			}
		})}
		l.serve.Add(1)
		go func() {
			defer l.serve.Done()
			defer l.cancel()
			_ = l.http.Serve(&trackedListener{Listener: serving, owner: l})
		}()
	}
	return l, nil
}
func (l *listener) publish(c net.Conn) bool {
	select {
	case <-l.ctx.Done():
		return false
	default:
	}
	select {
	case l.queue <- c:
		return true
	case <-l.ctx.Done():
		return false
	default:
		return false
	}
}
func (l *listener) Accept() (net.Conn, error) {
	for {
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
}
func (l *listener) Addr() net.Addr { return l.raw.Addr() }
func (l *listener) Close() error {
	l.once.Do(func() {
		l.cancel()
		l.raw.Close()
		if l.http != nil {
			l.http.Close()
		}
		if l.grpc != nil {
			l.grpc.Stop()
		}
		l.mu.Lock()
		all := make([]net.Conn, 0, len(l.connections))
		for c := range l.connections {
			all = append(all, c)
		}
		l.mu.Unlock()
		for _, c := range all {
			c.Close()
		}
		for {
			select {
			case c := <-l.queue:
				c.Close()
			default:
				goto drained
			}
		}
	drained:
		l.serve.Wait()
		l.handlers.Wait()
		l.mu.Lock()
		streams := make([]*grpcConn, 0, len(l.streams))
		for c := range l.streams {
			streams = append(streams, c)
		}
		l.mu.Unlock()
		for _, c := range streams {
			c.Close()
			<-c.joined
		}
		l.watchers.Wait()
		close(l.done)
	})
	<-l.done
	return nil
}

type trackedListener struct {
	net.Listener
	owner *listener
}

func (t *trackedListener) Accept() (net.Conn, error) {
	for {
		raw, e := t.Listener.Accept()
		if e != nil {
			return nil, e
		}
		t.owner.mu.Lock()
		if t.owner.ctx.Err() != nil || len(t.owner.connections) >= 512 {
			t.owner.mu.Unlock()
			raw.Close()
			if t.owner.ctx.Err() != nil {
				return nil, net.ErrClosed
			}
			continue
		}
		c := &trackedConn{Conn: raw, owner: t.owner}
		t.owner.connections[c] = true
		t.owner.mu.Unlock()
		return &wsSocket{Conn: c}, nil
	}
}

type trackedConn struct {
	net.Conn
	owner *listener
	once  sync.Once
}

func (c *trackedConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.owner.mu.Lock(); delete(c.owner.connections, c); c.owner.mu.Unlock() })
	return e
}
func (c *trackedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

func (l *listener) begin() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ctx.Err() != nil {
		return false
	}
	l.handlers.Add(1)
	return true
}
