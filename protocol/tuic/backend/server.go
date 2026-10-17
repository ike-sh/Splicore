// Package backend owns TUIC v5 connection and stream lifetimes over independent
// quic-go. Application layers use only net interfaces and semantic endpoints.
package backend

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/tuic/wire"
	"github.com/quic-go/quic-go"
)

type User struct{ ID, Password string }
type ServerConfig struct {
	TLS          *tls.Config
	Authenticate func([16]byte) (User, bool)
	TCP          func(context.Context, string, net.Conn, access.Endpoint) error
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
	peers           map[*quic.Conn]bool
	wg              sync.WaitGroup
	once            sync.Once
	done            chan struct{}
}

func quicConfig() *quic.Config {
	return &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 10 * time.Second, MaxIncomingStreams: 256, MaxIncomingUniStreams: 256, InitialStreamReceiveWindow: 8 << 20, MaxStreamReceiveWindow: 8 << 20, InitialConnectionReceiveWindow: 20 << 20, MaxConnectionReceiveWindow: 20 << 20}
}
func NewServer(ctx context.Context, packet net.PacketConn, c ServerConfig) (*Server, error) {
	var reset quic.StatelessResetKey
	if _, err := rand.Read(reset[:]); err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packet, StatelessResetKey: &reset}
	tc := c.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{"h3"}
	listener, err := transport.Listen(tc, quicConfig())
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	return &Server{config: c, packet: packet, transport: transport, listener: listener, ctx: ctx, cancel: cancel, peers: map[*quic.Conn]bool{}, done: make(chan struct{})}, nil
}
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

// Addr reports the retained UDP listener, including an atomic ephemeral bind.
func (s *Server) Addr() net.Addr { return s.packet.LocalAddr() }
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		q, err := s.listener.Accept(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed || len(s.peers) >= 256 {
			s.mu.Unlock()
			_ = q.CloseWithError(0, "")
			continue
		}
		s.peers[q] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(q)
	}
}
func (s *Server) Close(ctx context.Context) error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		peers := make([]*quic.Conn, 0, len(s.peers))
		for q := range s.peers {
			peers = append(peers, q)
		}
		s.mu.Unlock()
		s.cancel()
		_ = s.listener.Close()
		for _, q := range peers {
			_ = q.CloseWithError(0, "")
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

type delivery struct {
	d              wire.Datagram
	unidirectional bool
}
type peer struct {
	server   *Server
	q        *quic.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	auth     atomic.Pointer[User]
	authMu   sync.Mutex
	ready    chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   bool
	packets  map[uint16]*packetio.Queue
	incoming chan delivery
	writer   *packetio.Writer
}

func (s *Server) serve(q *quic.Conn) {
	defer s.wg.Done()
	defer func() { s.mu.Lock(); delete(s.peers, q); s.mu.Unlock() }()
	ctx, cancel := context.WithCancel(q.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	p := &peer{server: s, q: q, ctx: ctx, cancel: cancel, ready: make(chan struct{}), packets: map[uint16]*packetio.Queue{}, incoming: make(chan delivery, 128)}
	p.writer = packetio.NewWriter(ctx, q.SendDatagram)
	authDeadline := time.AfterFunc(3*time.Second, func() {
		if p.auth.Load() == nil {
			_ = q.CloseWithError(0, "")
		}
	})
	defer authDeadline.Stop()
	p.wg.Add(4)
	go p.streams()
	go p.commands()
	go p.datagrams()
	go p.packetsLoop()
	<-ctx.Done()
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	_ = q.CloseWithError(0, "")
	p.writer.Wait()
	p.wg.Wait()
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
func (p *peer) waitAuth() *User {
	select {
	case <-p.ready:
		return p.auth.Load()
	case <-p.ctx.Done():
		return nil
	}
}
func (p *peer) streams() {
	defer p.wg.Done()
	for {
		stream, err := p.q.AcceptStream(p.ctx)
		if err != nil {
			return
		}
		if !p.begin() {
			stream.CancelRead(0)
			stream.CancelWrite(0)
			return
		}
		go func() {
			defer p.wg.Done()
			c := &Stream{Stream: stream, q: p.q}
			defer c.Close()
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			command, err := wire.Head(stream)
			if err != nil || command != wire.Connect {
				return
			}
			dst, err := wire.ReadAddress(stream, false)
			if err != nil {
				return
			}
			user := p.waitAuth()
			if user == nil {
				return
			}
			_ = stream.SetReadDeadline(time.Time{})
			_ = p.server.config.TCP(p.ctx, user.ID, c, dst)
			_ = c.CloseWrite()
		}()
	}
}
func (p *peer) commands() {
	defer p.wg.Done()
	for {
		stream, err := p.q.AcceptUniStream(p.ctx)
		if err != nil {
			return
		}
		if !p.begin() {
			stream.CancelRead(0)
			return
		}
		go func() {
			defer p.wg.Done()
			defer stream.CancelRead(0)
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			command, err := wire.Head(stream)
			if err != nil {
				return
			}
			switch command {
			case wire.Authenticate:
				var b [48]byte
				if _, err := io.ReadFull(stream, b[:]); err != nil {
					return
				}
				var uuid [16]byte
				copy(uuid[:], b[:16])
				user, ok := p.server.config.Authenticate(uuid)
				if !ok {
					_ = p.q.CloseWithError(0, "")
					return
				}
				state := p.q.ConnectionState().TLS
				token, err := state.ExportKeyingMaterial(string(uuid[:]), []byte(user.Password), 32)
				if err != nil || subtle.ConstantTimeCompare(token, b[16:]) != 1 {
					_ = p.q.CloseWithError(0, "")
					return
				}
				p.authMu.Lock()
				prior := p.auth.Load()
				if prior == nil {
					snapshot := User{ID: user.ID}
					p.auth.Store(&snapshot)
					close(p.ready)
				} else if prior.ID != user.ID {
					_ = p.q.CloseWithError(0, "")
				}
				p.authMu.Unlock()
			case wire.Dissociate:
				if p.waitAuth() == nil {
					return
				}
				var id [2]byte
				if _, err := io.ReadFull(stream, id[:]); err != nil {
					return
				}
				p.mu.Lock()
				packet := p.packets[binary.BigEndian.Uint16(id[:])]
				delete(p.packets, binary.BigEndian.Uint16(id[:]))
				p.mu.Unlock()
				if packet != nil {
					_ = packet.Close()
				}
			case wire.Packet:
				// QUIC-mode packets are bounded before allocation. The managed profile
				// sends native datagrams, while references may select stream mode.
				var h [8]byte
				if _, err := io.ReadFull(stream, h[:]); err != nil {
					return
				}
				dst, err := wire.ReadAddress(stream, h[5] > 0)
				if err != nil {
					return
				}
				size := int(binary.BigEndian.Uint16(h[6:]))
				if size > wire.MaxPayload {
					return
				}
				d := wire.Datagram{Association: binary.BigEndian.Uint16(h[:]), ID: binary.BigEndian.Uint16(h[2:]), Count: h[4], Index: h[5], Destination: dst, Payload: make([]byte, size)}
				if _, err := io.ReadFull(stream, d.Payload); err != nil {
					return
				}
				select {
				case p.incoming <- delivery{d, true}:
				case <-p.ctx.Done():
				}
			}
		}()
	}
}
func (p *peer) datagrams() {
	defer p.wg.Done()
	for {
		b, err := p.q.ReceiveDatagram(p.ctx)
		if err != nil {
			return
		}
		if len(b) == 2 && b[0] == wire.Version && b[1] == wire.Heartbeat {
			continue
		}
		d, err := wire.Decode(b)
		if err != nil {
			continue
		}
		select {
		case p.incoming <- delivery{d, false}:
		case <-p.ctx.Done():
			return
		}
	}
}
func (p *peer) packetsLoop() {
	defer p.wg.Done()
	user := p.waitAuth()
	if user == nil {
		return
	}
	var assembly wire.Assembly
	for {
		var next delivery
		select {
		case next = <-p.incoming:
		case <-p.ctx.Done():
			return
		}
		d, ok := assembly.Add(next.d)
		if !ok {
			continue
		}
		p.mu.Lock()
		packet := p.packets[d.Association]
		if packet != nil && packet.Context().Err() != nil {
			delete(p.packets, d.Association)
			packet = nil
		}
		if packet == nil && !p.closed && p.ctx.Err() == nil && len(p.packets) < 128 {
			id := d.Association
			streamMode := next.unidirectional
			var sequence atomic.Uint32
			packet = packetio.New(p.ctx, p.q.LocalAddr(), func(writeCtx context.Context, b []byte, address net.Addr) error {
				dst, err := netaddr.From(address)
				if err != nil {
					return err
				}
				frames, err := wire.Fragments(id, uint16(sequence.Add(1)), dst, b)
				if err != nil {
					return err
				}
				for _, frame := range frames {
					if writeCtx.Err() != nil {
						return context.Cause(writeCtx)
					}
					if streamMode {
						if err = sendPacketStream(writeCtx, p.q, frame); err != nil {
							return err
						}
					} else if err := p.writer.Send(writeCtx, frame); err != nil {
						return err
					}
				}
				return nil
			})
			p.packets[id] = packet
			p.wg.Add(1)
			go func(packet *packetio.Queue) {
				defer p.wg.Done()
				defer packet.Close()
				_ = p.server.config.UDP(packet.Context(), user.ID, packet)
				p.mu.Lock()
				if p.packets[id] == packet {
					delete(p.packets, id)
				}
				p.mu.Unlock()
			}(packet)
		}
		p.mu.Unlock()
		if packet != nil {
			packet.Deliver(d.Payload, netaddr.UDP(d.Destination))
		}
	}
}

func sendPacketStream(ctx context.Context, q *quic.Conn, frame []byte) error {
	stream, err := q.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { stream.CancelWrite(0); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	// Preserve the existing per-stream transport bound in addition to the
	// association's live deadline/cancellation. Never set a parent deadline.
	_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err = wire.Write(stream, frame); err != nil {
		stream.CancelWrite(0)
		return err
	}
	return stream.Close()
}
