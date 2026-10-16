// Package backend owns Hysteria2 proxy streams, UDP sessions and dispatch.
// The specialized Hysteria transport owns QUIC/TLS/H3 admission and sockets.
package backend

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	ht "github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

type ServerConfig struct {
	TLS          *tls.Config
	Transport    cfg.Hysteria
	Authenticate func(string) (string, bool)
	TCP          func(context.Context, string, *Stream, access.Endpoint) error
	UDP          func(context.Context, string, net.PacketConn) error
}
type Server struct{ transport *ht.Server }

func NewServer(ctx context.Context, packet net.PacketConn, c ServerConfig) (*Server, error) {
	if c.TCP == nil || c.UDP == nil {
		if packet != nil {
			_ = packet.Close()
		}
		return nil, ht.ErrConfig
	}
	// Legacy zero transport settings migrate to version 2 on this single path.
	if c.Transport == (cfg.Hysteria{}) {
		c.Transport.Version = 2
	}
	s, e := ht.NewServer(ctx, packet, ht.ServerConfig{TLS: c.TLS, Settings: c.Transport, Authenticate: c.Authenticate, Application: func(conn *ht.Connection) ht.Hooks {
		p := &peer{config: c, connection: conn, packets: map[uint32]*session{}}
		return ht.Hooks{Dispatch: p.dispatch, Admitted: func() {
			if conn.UDP {
				conn.Go(p.receive)
			}
		}}
	}})
	if e != nil {
		return nil, e
	}
	return &Server{transport: s}, nil
}
func (s *Server) Start()                           { s.transport.Start() }
func (s *Server) Addr() net.Addr                   { return s.transport.Addr() }
func (s *Server) Close(ctx context.Context) error  { return s.transport.Close(ctx) }
func (s *Server) Congestion() []ht.CongestionState { return s.transport.Congestion() }

type session struct {
	packet *Packet
	last   time.Time
}
type peer struct {
	config     ServerConfig
	connection *ht.Connection
	mu         sync.Mutex
	packets    map[uint32]*session
	partial    atomic.Int64
}

func (p *peer) dispatch(ft http3.FrameType, stream *quic.Stream, e error) (bool, error) {
	if e != nil || ft != wire.TCPRequest {
		return false, nil
	}
	if !p.connection.Go(func() {
		c := &Stream{Stream: stream, connection: p.connection.QUIC}
		defer func() { _ = c.CloseWrite(); _ = c.Close() }()
		_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		frame, e := quicvarint.Read(quicvarint.NewReader(stream))
		if e != nil || frame != wire.TCPRequest {
			return
		}
		dst, e := wire.ReadRequest(stream)
		if e != nil {
			return
		}
		_ = stream.SetReadDeadline(time.Time{})
		if e = p.config.TCP(p.connection.Context(), p.connection.Identity(), c, dst); e != nil {
			_ = c.Reply(false)
		}
	}) {
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}
	return true, nil
}
func (p *peer) expire(now time.Time) []uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var expired []uint32
	for id, s := range p.packets {
		if s.packet.ctx.Err() != nil || !now.Before(s.last.Add(time.Duration(p.config.Transport.IdleSeconds())*time.Second)) {
			_ = s.packet.Close()
			delete(p.packets, id)
			expired = append(expired, id)
		}
	}
	return expired
}
func (p *peer) receive() {
	ctx := p.connection.Context()
	incoming := make(chan []byte, 16)
	if !p.connection.Go(func() {
		for {
			b, e := p.connection.ReceiveDatagram(ctx)
			if e != nil {
				return
			}
			select {
			case incoming <- b:
			case <-ctx.Done():
				return
			default:
			}
		}
	}) {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var fragments wire.Assembly
	defer func() {
		p.mu.Lock()
		for id, s := range p.packets {
			_ = s.packet.Close()
			delete(p.packets, id)
		}
		p.mu.Unlock()
		fragments.Clear()
		p.partial.Store(0)
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, id := range p.expire(now) {
				fragments.ForgetSession(id)
			}
			fragments.Sweep(now)
			p.partial.Store(int64(fragments.Pending()))
		case b := <-incoming:
			d, e := wire.DecodeDatagram(b)
			if e != nil {
				continue
			}
			d, complete := fragments.Add(d)
			p.partial.Store(int64(fragments.Pending()))
			if !complete {
				continue
			}
			p.mu.Lock()
			s := p.packets[d.Session]
			if s != nil && s.packet.ctx.Err() != nil {
				delete(p.packets, d.Session)
				s = nil
				fragments.ForgetSession(d.Session)
			}
			if s == nil && ctx.Err() == nil && len(p.packets) < 128 {
				packet := newCarrierPacket(p.connection, d.Session)
				s = &session{packet: packet, last: time.Now()}
				p.packets[d.Session] = s
				packet.touch = func() {
					p.mu.Lock()
					if current := p.packets[packet.session]; current != nil && current.packet == packet {
						current.last = time.Now()
					}
					p.mu.Unlock()
				}
				if !p.connection.Go(func() {
					defer packet.Close()
					_ = p.config.UDP(packet.ctx, p.connection.Identity(), packet)
					p.mu.Lock()
					if current := p.packets[packet.session]; current != nil && current.packet == packet {
						delete(p.packets, packet.session)
					}
					p.mu.Unlock()
				}) {
					delete(p.packets, d.Session)
					_ = packet.Close()
					s = nil
				}
			}
			if s != nil {
				s.last = time.Now()
			}
			p.mu.Unlock()
			if s != nil {
				s.packet.deliver(d)
			}
		}
	}
}
