// Package backend owns Hysteria2 connection, stream and datagram lifetimes.
// Domain and application layers receive only owned endpoints and net interfaces.
package backend

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

type ServerConfig struct {
	TLS          *tls.Config
	Authenticate func(string) (string, bool)
	TCP          func(context.Context, string, *Stream, access.Endpoint) error
	UDP          func(context.Context, string, net.PacketConn) error
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
	connections     map[*quic.Conn]bool
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
}

func NewServer(ctx context.Context, packet net.PacketConn, c ServerConfig) (*Server, error) {
	var reset quic.StatelessResetKey
	if _, err := rand.Read(reset[:]); err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packet, StatelessResetKey: &reset}
	tlsConfig := http3.ConfigureTLSConfig(c.TLS.Clone())
	listener, err := transport.Listen(tlsConfig, quicConfig())
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Server{config: c, packet: packet, transport: transport, listener: listener, ctx: ctx, cancel: cancel, connections: map[*quic.Conn]bool{}, done: make(chan struct{})}, nil
}
func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxDatagramFrameSize: 1200, AssumePeerMaxDatagramFrameSize: 1200, DisablePathManager: true, InitialStreamReceiveWindow: 8 << 20, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 20 << 20, MaxConnectionReceiveWindow: 20 << 20, MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: 256}
}

// Start orders the accept worker's Add before any Close can Wait.
func (s *Server) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.started {
		return
	}
	s.started = true
	s.wg.Add(1)
	go s.accept()
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed || len(s.connections) >= 256 {
			s.mu.Unlock()
			_ = c.CloseWithError(0x107, "")
			continue
		}
		s.connections[c] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(c)
	}
}
func (s *Server) Close(ctx context.Context) error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		all := make([]*quic.Conn, 0, len(s.connections))
		for c := range s.connections {
			all = append(all, c)
		}
		s.mu.Unlock()
		s.cancel()
		_ = s.listener.Close()
		for _, c := range all {
			_ = c.CloseWithError(0x100, "")
		}
		_ = s.transport.Close()
		_ = s.packet.Close()
		go func() { s.wg.Wait(); close(s.done) }()
	})
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) serve(c *quic.Conn) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock() }()
	ctx, cancel := context.WithCancel(c.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	p := &peer{server: s, connection: c, ctx: ctx, cancel: cancel, packets: map[uint32]*Packet{}}
	p.writer = packetio.NewWriter(ctx, c.SendDatagram)
	h3 := &http3.Server{Handler: p, StreamDispatcher: p.dispatch}
	_ = h3.ServeQUICConn(c)
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	cancel()
	_ = c.CloseWithError(0x100, "")
	_ = h3.Close()
	p.writer.Wait()
	p.wg.Wait()
}

type authenticated struct{ id string }
type peer struct {
	server     *Server
	connection *quic.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	authMu     sync.Mutex
	auth       atomic.Pointer[authenticated]
	mu         sync.Mutex
	closed     bool
	wg         sync.WaitGroup
	packets    map[uint32]*Packet
	writer     *packetio.Writer
}

func (p *peer) begin() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ctx.Err() != nil {
		return false
	}
	p.wg.Add(1)
	return true
}
func (p *peer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Host != "hysteria" || r.URL.Path != "/auth" {
		http.NotFound(w, r)
		return
	}
	padding, err := wire.Padding(256, 2048)
	if err != nil {
		http.Error(w, "Authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	p.authMu.Lock()
	defer p.authMu.Unlock()
	user := p.auth.Load()
	if user == nil {
		id, ok := p.server.config.Authenticate(r.Header.Get("Hysteria-Auth"))
		if !ok || !p.begin() {
			http.NotFound(w, r)
			return
		}
		user = &authenticated{id: id}
		p.auth.Store(user)
		go p.receive(user.id)
	}
	w.Header().Set("Hysteria-UDP", "true")
	w.Header().Set("Hysteria-CC-RX", "auto")
	w.Header().Set("Hysteria-Padding", padding)
	w.WriteHeader(233)
}
func (p *peer) dispatch(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	user := p.auth.Load()
	if err != nil || user == nil || ft != wire.TCPRequest {
		return false, nil
	}
	if !p.begin() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return true, nil
	}
	go func() {
		defer p.wg.Done()
		c := &Stream{Stream: stream, connection: p.connection}
		defer func() { _ = c.CloseWrite(); _ = c.Close() }()
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return
		}
		dst, err := wire.ReadRequest(stream)
		if err != nil {
			return
		}
		_ = stream.SetReadDeadline(time.Time{})
		if err := p.server.config.TCP(p.ctx, user.id, c, dst); err != nil {
			_ = c.Reply(false)
		}
	}()
	return true, nil
}
func (p *peer) receive(id string) {
	defer p.wg.Done()
	var fragments wire.Assembly
	for {
		b, err := p.connection.ReceiveDatagram(p.ctx)
		if err != nil {
			return
		}
		d, err := wire.DecodeDatagram(b)
		if err != nil {
			continue
		}
		d, complete := fragments.Add(d)
		if !complete {
			continue
		}
		p.mu.Lock()
		packet := p.packets[d.Session]
		if packet != nil && packet.ctx.Err() != nil {
			delete(p.packets, d.Session)
			packet = nil
		}
		if packet == nil && !p.closed && p.ctx.Err() == nil && len(p.packets) < 128 {
			packet = newPacket(p.ctx, p.connection.LocalAddr(), d.Session, p.writer.Send)
			p.packets[d.Session] = packet
			p.wg.Add(1)
			go func(packet *Packet) {
				defer p.wg.Done()
				defer packet.Close()
				_ = p.server.config.UDP(packet.ctx, id, packet)
				p.mu.Lock()
				if p.packets[packet.session] == packet {
					delete(p.packets, packet.session)
				}
				p.mu.Unlock()
			}(packet)
		}
		p.mu.Unlock()
		if packet != nil {
			packet.deliver(d)
		}
	}
}
