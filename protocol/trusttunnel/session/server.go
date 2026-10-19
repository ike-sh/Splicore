package session

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"golang.org/x/net/http2"
)

type ServerConfig struct {
	TLS                                         *tls.Config
	HTTP2, HTTP3                                bool
	MaxStreams, MaxSessions, MaxFlows           int
	ConnectTimeout, IdleTimeout, UDPIdleTimeout time.Duration
	Authenticate                                func(username, password string) (string, bool)
	DialTCP                                     func(context.Context, string, string) (net.Conn, error)
	DialUDP                                     func(context.Context, string, string) (net.Conn, error)
	Relay                                       func(context.Context, string, net.Conn, net.Conn)
	Echo                                        EchoBackend
}

func (ServerConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("TrustTunnelServerConfig{[REDACTED]}"))
}

type serverSession struct {
	mu             sync.Mutex
	user           string
	reserved       map[string]bool
	ctx            context.Context
	cancel         context.CancelFunc
	closeTransport func()
}
type sessionKey struct{}
type Server struct {
	config     ServerConfig
	ctx        context.Context
	cancel     context.CancelFunc
	h2         *http.Server
	h3         *h3Server
	mu         sync.Mutex
	closed     bool
	sessions   map[*serverSession]bool
	h2sessions map[net.Conn]*serverSession
	handlers   sync.WaitGroup
	capacity   chan struct{}
}

func NewServer(c ServerConfig) (*Server, error) {
	if c.TLS == nil || len(c.TLS.Certificates) == 0 || !c.HTTP2 && !c.HTTP3 || c.HTTP3 && !H3Enabled() || c.Authenticate == nil || c.DialTCP == nil || c.DialUDP == nil || c.Relay == nil {
		return nil, failure(Config, nil)
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = 512
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 64
	}
	if c.MaxFlows == 0 {
		c.MaxFlows = 256
	}
	if c.MaxStreams < 4 || c.MaxStreams > 512 || c.MaxSessions < 1 || c.MaxSessions > 1024 || c.MaxFlows < 1 || c.MaxFlows > 4096 {
		return nil, failure(Config, nil)
	}
	for _, v := range []struct {
		p *time.Duration
		d time.Duration
	}{{&c.ConnectTimeout, 30 * time.Second}, {&c.IdleTimeout, 10 * time.Minute}, {&c.UDPIdleTimeout, 120 * time.Second}} {
		if *v.p == 0 {
			*v.p = v.d
		}
		if *v.p < time.Millisecond || *v.p > 24*time.Hour {
			return nil, failure(Config, nil)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{config: c, ctx: ctx, cancel: cancel, sessions: map[*serverSession]bool{}, h2sessions: map[net.Conn]*serverSession{}, capacity: make(chan struct{}, c.MaxStreams)}
	tc := c.TLS.Clone()
	tc.MinVersion = max(tc.MinVersion, tls.VersionTLS12)
	tc.NextProtos = []string{"h2"}
	s.h2 = &http.Server{Handler: s, TLSConfig: tc, ReadHeaderTimeout: c.ConnectTimeout, IdleTimeout: c.IdleTimeout, MaxHeaderBytes: maxHeaders, BaseContext: func(net.Listener) context.Context { return ctx }, ConnContext: func(ctx context.Context, n net.Conn) context.Context {
		v := s.newSession(ctx, func() { _ = n.Close() })
		s.mu.Lock()
		s.h2sessions[n] = v
		s.mu.Unlock()
		return context.WithValue(ctx, sessionKey{}, v)
	}, ConnState: func(n net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			s.mu.Lock()
			v := s.h2sessions[n]
			delete(s.h2sessions, n)
			delete(s.sessions, v)
			s.mu.Unlock()
			if v != nil {
				v.cancel()
			}
		}
	}}
	if e := http2.ConfigureServer(s.h2, &http2.Server{MaxConcurrentStreams: uint32(c.MaxStreams), MaxUploadBufferPerStream: 131072, MaxUploadBufferPerConnection: 8 << 20}); e != nil {
		cancel()
		return nil, failure(HTTP, e)
	}
	s.h3 = newH3Server(c, s, func(ctx context.Context, close func()) context.Context {
		v := s.newSession(ctx, close)
		context.AfterFunc(ctx, func() { v.cancel(); s.mu.Lock(); delete(s.sessions, v); s.mu.Unlock() })
		return context.WithValue(ctx, sessionKey{}, v)
	})
	return s, nil
}
func (s *Server) newSession(ctx context.Context, closeTransport func()) *serverSession {
	life, cancel := context.WithCancel(ctx)
	v := &serverSession{reserved: map[string]bool{}, ctx: life, cancel: cancel, closeTransport: closeTransport}
	s.mu.Lock()
	if s.closed || len(s.sessions) >= s.config.MaxSessions {
		s.mu.Unlock()
		cancel()
		closeTransport()
		return v
	}
	s.sessions[v] = true
	s.mu.Unlock()
	return v
}
func (s *Server) ServeTCP(l net.Listener) error {
	if !s.config.HTTP2 {
		return failure(Config, nil)
	}
	return s.h2.ServeTLS(l, "", "")
}
func (s *Server) ServeUDP(p net.PacketConn) error {
	if !s.config.HTTP3 {
		return failure(Config, nil)
	}
	return s.h3.serve(p)
}
func (s *Server) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	s.cancel()
	all := make([]*serverSession, 0, len(s.sessions))
	for v := range s.sessions {
		all = append(all, v)
	}
	s.mu.Unlock()
	for _, v := range all {
		v.cancel()
		v.closeTransport()
	}
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
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		http.Error(w, "unavailable", 503)
		return
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	v, ok := r.Context().Value(sessionKey{}).(*serverSession)
	if !ok || v.ctx.Err() != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	if r.Method != "CONNECT" || r.ProtoMajor != 2 && r.ProtoMajor != 3 || r.URL == nil || r.URL.Path != "" || r.URL.RawQuery != "" {
		http.Error(w, "invalid CONNECT", 400)
		return
	}
	ua := r.Header.Values("User-Agent")
	auth := r.Header.Values("Proxy-Authorization")
	if len(ua) != 1 || ua[0] == "" || len(ua[0]) > 518 || len(auth) != 1 {
		s.unauthorized(w)
		return
	}
	u, p, e := wire.Basic(auth[0])
	if e != nil {
		s.unauthorized(w)
		return
	}
	user, accepted := s.config.Authenticate(u, p)
	if !accepted || user == "" {
		s.unauthorized(w)
		return
	}
	v.mu.Lock()
	if v.user != "" && v.user != user {
		v.mu.Unlock()
		s.unauthorized(w)
		return
	}
	v.user = user
	v.mu.Unlock()
	reserved := r.Host == "_udp2" || r.Host == "_icmp" || r.Host == "_check"
	if !reserved {
		if _, e := wire.Authority(r.Host); e != nil {
			http.Error(w, "invalid target", 400)
			return
		}
	}
	select {
	case s.capacity <- struct{}{}:
		defer func() { <-s.capacity }()
	default:
		http.Error(w, "capacity", 503)
		return
	}
	if r.Host == "_check" {
		w.WriteHeader(200)
		return
	}
	if r.Host == "_udp2" || r.Host == "_icmp" {
		if !strings.HasSuffix(ua[0], r.Host) {
			http.Error(w, "invalid user agent", 400)
			return
		}
		v.mu.Lock()
		duplicate := v.reserved[r.Host]
		if !duplicate {
			v.reserved[r.Host] = true
		}
		v.mu.Unlock()
		if duplicate {
			http.Error(w, "duplicate reserved stream", 409)
			return
		}
		defer func() { v.mu.Lock(); delete(v.reserved, r.Host); v.mu.Unlock() }()
		if r.Host == "_icmp" && s.config.Echo == nil {
			http.Error(w, "ICMP unavailable", 503)
			return
		}
	}
	ctx, cancel := context.WithCancel(v.ctx)
	defer cancel()
	stopRequest := context.AfterFunc(r.Context(), cancel)
	defer stopRequest()
	stopServer := context.AfterFunc(s.ctx, cancel)
	defer stopServer()
	var target net.Conn
	if !reserved {
		dial, cancelDial := context.WithTimeout(ctx, s.config.ConnectTimeout)
		target, e = s.config.DialTCP(dial, user, r.Host)
		cancelDial()
		if e != nil {
			http.Error(w, "destination unavailable", 502)
			return
		}
		defer target.Close()
	}
	w.WriteHeader(200)
	if http.NewResponseController(w).Flush() != nil {
		return
	}
	var stream net.Conn
	if r.ProtoMajor == 3 {
		stopRequest()
		stream, ok = takeH3(w, r, s.config.IdleTimeout, cancel)
		if !ok {
			return
		}
	} else {
		controller := http.NewResponseController(w)
		// net/http has no independent response END_STREAM operation. Once the
		// target ends its response, finish this logical CONNECT after flushed
		// bytes, interrupting any remaining upload. Client upload half-close
		// still leaves the response readable until the target finishes.
		stream = newBodyConn(r.Body, flushWriter{w}, func() error { cancel(); return nil }, func(graceful bool) {
			_ = r.Body.Close()
			if !graceful {
				_ = controller.SetWriteDeadline(time.Now())
			}
		}, streamAddr("trusttunnel-server"), streamAddr(r.RemoteAddr), s.config.IdleTimeout)
	}
	defer stream.Close()
	stopStream := context.AfterFunc(ctx, func() {
		_ = stream.Close()
		if target != nil {
			_ = target.Close()
		}
	})
	defer stopStream()
	switch r.Host {
	case "_udp2":
		s.serveUDP(ctx, user, stream)
	case "_icmp":
		s.serveEcho(ctx, user, stream)
	default:
		s.config.Relay(ctx, user, stream, target)
	}
}
func (s *Server) unauthorized(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="TrustTunnel"`)
	http.Error(w, "authentication required", 407)
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, e := f.w.Write(p)
	if e == nil {
		e = http.NewResponseController(f.w).Flush()
	}
	return n, e
}
