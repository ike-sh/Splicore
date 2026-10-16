package hysteria

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type Hooks struct {
	Dispatch func(http3.FrameType, *quic.Stream, error) (bool, error)
	Admitted func()
}
type ServerConfig struct {
	TLS          *tls.Config
	Settings     cfg.Hysteria
	Authenticate func(string) (string, bool)
	Application  func(*Connection) Hooks
}
type Server struct {
	config          ServerConfig
	packet          net.PacketConn
	transport       *quic.Transport
	listener        *quic.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.Mutex
	closed, started bool
	connections     map[*quic.Conn]*Connection
	workers         sync.WaitGroup
	once            sync.Once
	done            chan struct{}
	mask            http.Handler
	closeMask       func()
}

// NewServer consumes packet ownership, including all initialization failures.
func NewServer(ctx context.Context, packet net.PacketConn, c ServerConfig) (*Server, error) {
	if packet == nil {
		return nil, ErrConfig
	}
	fail := func(e error) (*Server, error) { _ = packet.Close(); return nil, e }
	if !validTLS(c.TLS) || len(c.TLS.Certificates) == 0 && c.TLS.GetCertificate == nil || c.Authenticate == nil || c.Application == nil || c.Settings.Validate() != nil {
		return fail(ErrConfig)
	}
	c.Settings = c.Settings.Clone()
	c.TLS = snapshotTLS(c.TLS)
	c.TLS.MinVersion = tls.VersionTLS13
	c.TLS.NextProtos = []string{"h3"}
	mask, closeMask, e := masquerade(c.Settings.Masquerade)
	if e != nil {
		return fail(e)
	}
	var key quic.StatelessResetKey
	if _, e = rand.Read(key[:]); e != nil {
		closeMask()
		return fail(e)
	}
	tr := &quic.Transport{Conn: packet, StatelessResetKey: &key}
	ln, e := tr.Listen(http3.ConfigureTLSConfig(c.TLS), carrier(c.Settings.QUIC))
	if e != nil {
		_ = tr.Close()
		closeMask()
		return fail(e)
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Server{config: c, packet: packet, transport: tr, listener: ln, ctx: ctx, cancel: cancel, connections: map[*quic.Conn]*Connection{}, done: make(chan struct{}), mask: mask, closeMask: closeMask}, nil
}
func (s *Server) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started {
		return
	}
	s.started = true
	s.workers.Add(1)
	go s.accept()
}
func (s *Server) ActiveConnections() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.connections) }
func (s *Server) Congestion() []CongestionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var all []CongestionState
	for _, c := range s.connections {
		if c != nil && c.admitted.Load() {
			all = append(all, c.Congestion())
		}
	}
	return all
}
func (s *Server) Addr() net.Addr { return s.packet.LocalAddr() }
func (s *Server) accept() {
	defer s.workers.Done()
	for {
		q, e := s.listener.Accept(s.ctx)
		if e != nil {
			return
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= 256 {
			s.mu.Unlock()
			_ = q.CloseWithError(0x107, "")
			continue
		}
		s.connections[q] = nil
		s.workers.Add(1)
		s.mu.Unlock()
		go s.serve(q)
	}
}
func (s *Server) Close(ctx context.Context) error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		all := make([]*quic.Conn, 0, len(s.connections))
		for q := range s.connections {
			all = append(all, q)
		}
		s.mu.Unlock()
		s.cancel()
		_ = s.listener.Close()
		for _, q := range all {
			_ = q.CloseWithError(0x100, "")
		}
		_ = s.transport.Close()
		_ = s.packet.Close()
		go func() { s.workers.Wait(); s.closeMask(); close(s.done) }()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) serve(q *quic.Conn) {
	defer s.workers.Done()
	defer func() { s.mu.Lock(); delete(s.connections, q); s.mu.Unlock() }()
	c := newConnection(q, nil)
	s.mu.Lock()
	s.connections[q] = c
	s.mu.Unlock()
	c.UDP = !s.config.Settings.DisableUDP
	c.startDatagrams()
	hooks := s.config.Application(c)
	p := &admission{server: s, conn: c, hooks: hooks}
	h3 := &http3.Server{Handler: p, MaxHeaderBytes: 16 << 10, StreamDispatcher: p.dispatch}
	_ = h3.ServeQUICConn(q)
	_ = h3.Close()
	c.Close()
}

type admission struct {
	server     *Server
	conn       *Connection
	hooks      Hooks
	mu         sync.Mutex
	credential [32]byte
}

func (p *admission) dispatch(ft http3.FrameType, stream *quic.Stream, e error) (bool, error) {
	if p.conn.Identity() == "" || p.hooks.Dispatch == nil {
		return false, nil
	}
	return p.hooks.Dispatch(ft, stream, e)
}
func (p *admission) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.conn.handle(func() { p.serveHTTP(w, r) })
}
func (p *admission) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != "hysteria" || r.URL.Path != "/auth" {
		p.server.mask.ServeHTTP(w, r)
		return
	}
	password := r.Header.Get("Hysteria-Auth")
	if len(password) == 0 || len(password) > 1024 {
		p.server.mask.ServeHTTP(w, r)
		return
	}
	if _, _, e := CCRX(r.Header.Get("Hysteria-CC-RX"), false); e != nil {
		p.server.mask.ServeHTTP(w, r)
		return
	}
	pad, e := padding()
	if e != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	digest := sha256.Sum256([]byte(password))
	p.mu.Lock()
	id := p.conn.Identity()
	if id == "" {
		var ok bool
		id, ok = p.server.config.Authenticate(password)
		if !ok || id == "" || p.conn.Context().Err() != nil || r.Context().Err() != nil {
			p.mu.Unlock()
			p.server.mask.ServeHTTP(w, r)
			return
		}
		p.credential = digest
		selected, e := chooseCongestion(p.server.config.Settings.QUIC, r.Header.Get("Hysteria-CC-RX"), true)
		if e != nil {
			p.mu.Unlock()
			p.server.mask.ServeHTTP(w, r)
			return
		}
		p.conn.mu.Lock()
		p.conn.congestion = selected
		p.conn.controller = installCongestion(p.conn.QUIC, selected)
		p.conn.mu.Unlock()
		p.conn.identity.Store(&id)
		p.conn.admitted.Store(true)
		if p.hooks.Admitted != nil {
			p.hooks.Admitted()
		}
	} else if p.credential != digest {
		p.mu.Unlock()
		p.server.mask.ServeHTTP(w, r)
		return
	}
	p.mu.Unlock()
	udp := "false"
	if p.conn.UDP {
		udp = "true"
	}
	w.Header().Set("Hysteria-UDP", udp)
	w.Header().Set("Hysteria-CC-RX", receiveRate(p.server.config.Settings.QUIC, true))
	w.Header().Set("Hysteria-Padding", pad)
	w.WriteHeader(233)
}
