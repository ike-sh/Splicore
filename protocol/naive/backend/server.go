package backend

import (
	"context"
	"crypto/tls"
	httpproxy "github.com/ike-sh/Splicore/internal/splicore/protocol/http"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type ServerConfig struct {
	TLS                         *tls.Config
	Mode                        string
	MaxStreams                  int
	ConnectTimeout, IdleTimeout time.Duration
	Authenticate                func(username, password string) (string, bool)
	Dial                        func(context.Context, string, string) (net.Conn, error)
	Relay                       func(context.Context, string, net.Conn, net.Conn)
}
type http3Server interface {
	serve(net.PacketConn) error
	close() error
}
type Server struct {
	config   ServerConfig
	ctx      context.Context
	cancel   context.CancelFunc
	h2       *http.Server
	h3       http3Server
	capacity chan struct{}
	mu       sync.Mutex
	closed   bool
	handlers sync.WaitGroup
}

func NewServer(config ServerConfig) (*Server, error) {
	if config.TLS == nil || config.Authenticate == nil || config.Dial == nil || config.Relay == nil || config.Mode != "https" && config.Mode != "quic" {
		return nil, ErrProtocol
	}
	if config.Mode == "quic" && !H3Enabled() {
		return nil, ErrProtocol
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = 512
	}
	if config.MaxStreams < 1 || config.MaxStreams > 512 {
		return nil, ErrProtocol
	}
	if config.ConnectTimeout == 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	if config.IdleTimeout == 0 {
		config.IdleTimeout = 10 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: config, ctx: ctx, cancel: cancel, capacity: make(chan struct{}, config.MaxStreams)}
	tc := config.TLS.Clone()
	tc.NextProtos = []string{"h2"}
	s.h2 = &http.Server{Handler: s, TLSConfig: tc, ReadHeaderTimeout: config.ConnectTimeout, IdleTimeout: config.IdleTimeout, MaxHeaderBytes: MaxHeaders,
		BaseContext: func(net.Listener) context.Context { return ctx }}
	if err := http2.ConfigureServer(s.h2, &http2.Server{MaxConcurrentStreams: uint32(config.MaxStreams), MaxUploadBufferPerConnection: 4 << 20, MaxUploadBufferPerStream: 1 << 20}); err != nil {
		cancel()
		return nil, err
	}
	s.h3 = newH3Server(config.TLS, s, config.MaxStreams, config.IdleTimeout)
	return s, nil
}
func (s *Server) ServeTCP(listener net.Listener) error { return s.h2.ServeTLS(listener, "", "") }
func (s *Server) ServeUDP(packet net.PacketConn) error { return s.h3.serve(packet) }
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.cancel()
	}
	s.mu.Unlock()
	_ = s.h2.Close()
	_ = s.h3.close()
	done := make(chan struct{})
	go func() { s.handlers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = io.WriteString(w, "<!doctype html><html><title>Welcome</title><body>Welcome</body></html>\n")
		}
		return
	}
	if req.Method != http.MethodConnect {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.ProtoMajor != 2 && req.ProtoMajor != 3 {
		http.Error(w, "HTTP/2 or HTTP/3 required", http.StatusHTTPVersionNotSupported)
		return
	}
	if req.URL == nil || req.URL.Path != "" || req.URL.RawQuery != "" {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	if _, err := httpproxy.Authority(req.Host); err != nil {
		http.Error(w, "invalid target", http.StatusBadRequest)
		return
	}
	auth := req.Header.Values("Proxy-Authorization")
	padding, err := paddingOffered(req.Header)
	if len(auth) > 1 || err != nil {
		http.Error(w, "invalid headers", http.StatusBadRequest)
		return
	}
	if len(auth) != 1 {
		s.unauthorized(w)
		return
	}
	pair, err := httpproxy.Basic(auth[0])
	if err != nil {
		s.unauthorized(w)
		return
	}
	user, ok := s.config.Authenticate(pair.Username, pair.Password)
	if !ok {
		s.unauthorized(w)
		return
	}
	select {
	case s.capacity <- struct{}{}:
		defer func() { <-s.capacity }()
	default:
		http.Error(w, "capacity reached", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	dialCtx, stopDial := context.WithTimeout(ctx, s.config.ConnectTimeout)
	target, err := s.config.Dial(dialCtx, user, req.Host)
	stopDial()
	if err != nil {
		http.Error(w, "destination unavailable", http.StatusBadGateway)
		return
	}
	if req.ProtoMajor == 3 {
		// Handler and relay share terminal paths; one owner closes the socket.
		target = &ownedTargetConn{Conn: target}
	}
	defer target.Close()
	if padding {
		value, err := HeaderPadding(true)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Padding", value)
	}
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return
	}
	var conn net.Conn
	if req.ProtoMajor == 3 {
		// Normal response FIN cancels QUIC's sending context. Preserve that
		// directional completion, but forward fatal stream and idle termination.
		tunnelCtx, stopTunnel := context.WithCancel(h3TunnelContext(req))
		defer stopTunnel()
		stopShutdown := context.AfterFunc(s.ctx, stopTunnel)
		defer stopShutdown()
		var taken bool
		conn, taken = takeH3Stream(w, req, s.config.IdleTimeout, stopTunnel)
		if !taken {
			return
		}
		ctx = tunnelCtx
	} else {
		controller := http.NewResponseController(w)
		// ResponseWriter has no independent H2 CloseWrite operation. Keep the
		// handler and request body alive after target sending EOF: relay joins
		// both directions, and handler return then emits response END_STREAM.
		// Response bytes are flushed immediately while upload can continue.
		body := newBodyConn(req.Body, flushWriter{w: w}, func() error { return nil },
			func(graceful bool) {
				_ = req.Body.Close()
				if !graceful {
					_ = controller.SetWriteDeadline(time.Now())
				}
			}, streamAddr("naive-server"), streamAddr(req.RemoteAddr), s.config.IdleTimeout)
		conn = body
	}
	defer conn.Close()
	if padding {
		conn = Padded(conn)
	}
	joined := make(chan struct{})
	go func() { s.config.Relay(ctx, user, conn, target); close(joined) }()
	select {
	case <-joined:
	case <-ctx.Done():
		_ = conn.Close()
		_ = target.Close()
		<-joined
	}
}

// ownedTargetConn keeps the underlying target Close exactly once when handler,
// relay cancellation and relay finalization converge. Normal upload EOF forwards
// only CloseWrite so the target can still send its response.
type ownedTargetConn struct {
	net.Conn
	once sync.Once
	err  error
}

func (c *ownedTargetConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}
func (c *ownedTargetConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Close()
}

func (s *Server) unauthorized(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
	http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if err == nil {
		err = http.NewResponseController(f.w).Flush()
	}
	return n, err
}
