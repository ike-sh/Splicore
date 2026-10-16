package backend

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	ht "github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

type ClientConfig struct {
	TLS       *tls.Config
	Password  string
	Socket    func(context.Context) (net.PacketConn, net.Addr, error)
	Transport cfg.Hysteria
}

// Client owns protocol datagram demultiplexers above its instance-scoped
// transport. Closing a stream or UDP child preserves all sibling sessions.
type Client struct {
	manager *ht.Manager
	mu      sync.Mutex
	closed  bool
	peers   map[*ht.Connection]*clientPeer
}
type clientPeer struct {
	connection *ht.Connection
	mu         sync.Mutex
	packets    map[uint32]*Packet
	next       uint32
}

func NewClient(ctx context.Context, c ClientConfig) (*Client, error) {
	if c.Transport == (cfg.Hysteria{}) {
		c.Transport.Version = 2
	}
	m, e := ht.NewManager(ctx, ht.ClientConfig{TLS: c.TLS, Password: c.Password, Socket: c.Socket, Settings: c.Transport})
	if e != nil {
		return nil, e
	}
	return &Client{manager: m, peers: map[*ht.Connection]*clientPeer{}}, nil
}
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.manager.Close()
	c.mu.Lock()
	clear(c.peers)
	c.mu.Unlock()
}
func (c *Client) Congestion() []ht.CongestionState { return c.manager.Congestion() }
func (c *Client) OpenTCP(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, wire.ErrFrame
	}
	q, e := c.manager.Acquire(ctx)
	if e != nil {
		return nil, e
	}
	stream, e := q.OpenStream(ctx)
	if e != nil {
		return nil, e
	}
	conn := &Stream{Stream: stream, connection: q.QUIC}
	canceled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(canceled) })
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	if e = wire.WriteRequest(stream, dst); e == nil {
		e = wire.ReadResponse(stream)
	}
	if !stop() {
		<-canceled
	}
	if ctx.Err() != nil {
		e = ctx.Err()
	}
	if e != nil {
		_ = conn.Close()
		return nil, e
	}
	_ = stream.SetDeadline(time.Time{})
	return conn, nil
}
func (c *Client) peer(q *ht.Connection) (*clientPeer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || q.Context().Err() != nil {
		return nil, net.ErrClosed
	}
	if p := c.peers[q]; p != nil {
		return p, nil
	}
	var seed [4]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return nil, e
	}
	p := &clientPeer{connection: q, packets: map[uint32]*Packet{}, next: binary.BigEndian.Uint32(seed[:])}
	c.peers[q] = p
	if !q.Go(func() { p.receive(); c.mu.Lock(); delete(c.peers, q); c.mu.Unlock() }) {
		delete(c.peers, q)
		return nil, net.ErrClosed
	}
	return p, nil
}
func (c *Client) OpenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if dst.Validate() != nil {
		return nil, wire.ErrFrame
	}
	q, e := c.manager.Acquire(ctx)
	if e != nil {
		return nil, e
	}
	if !q.UDP {
		return nil, wire.ErrRejected
	}
	peer, e := c.peer(q)
	if e != nil {
		return nil, e
	}
	peer.mu.Lock()
	defer peer.mu.Unlock()
	for id, p := range peer.packets {
		if p.ctx.Err() != nil {
			delete(peer.packets, id)
		}
	}
	if len(peer.packets) >= 128 || q.Context().Err() != nil {
		return nil, net.ErrClosed
	}
	peer.next++
	for peer.packets[peer.next] != nil {
		peer.next++
	}
	p := newCarrierPacket(q, peer.next)
	peer.packets[peer.next] = p
	p.afterClose = func() {
		peer.mu.Lock()
		if peer.packets[p.session] == p {
			delete(peer.packets, p.session)
		}
		peer.mu.Unlock()
	}
	return &DefaultPacket{PacketConn: p, Destination: dst}, nil
}
func (p *clientPeer) receive() {
	var fragments wire.Assembly
	defer func() {
		p.mu.Lock()
		all := make([]*Packet, 0, len(p.packets))
		for _, packet := range p.packets {
			all = append(all, packet)
		}
		clear(p.packets)
		p.mu.Unlock()
		for _, packet := range all {
			_ = packet.Close()
		}
		fragments.Clear()
	}()
	for {
		ctx, cancel := context.WithTimeout(p.connection.Context(), time.Second)
		b, e := p.connection.ReceiveDatagram(ctx)
		cancel()
		fragments.Sweep(time.Now())
		if p.connection.Context().Err() != nil {
			return
		}
		if e != nil {
			continue
		}
		d, e := wire.DecodeDatagram(b)
		if e != nil {
			continue
		}
		p.mu.Lock()
		packet := p.packets[d.Session]
		p.mu.Unlock()
		if packet == nil || packet.ctx.Err() != nil {
			fragments.ForgetSession(d.Session)
			continue
		}
		if d, ok := fragments.Add(d); ok {
			packet.deliver(d)
		}
	}
}

// Legacy per-flow APIs consume the same transport with private ownership.
func OpenTCP(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.Conn, error) {
	c, e := NewClient(ctx, config)
	if e != nil {
		return nil, e
	}
	flow, e := c.OpenTCP(ctx, dst)
	if e != nil {
		c.Close()
		return nil, e
	}
	flow.(*Stream).afterClose = c.Close
	return flow, nil
}

type privatePacket struct {
	net.PacketConn
	client *Client
	once   sync.Once
}

func (p *privatePacket) Close() error {
	p.once.Do(func() { _ = p.PacketConn.Close(); p.client.Close() })
	return nil
}
func OpenPacket(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.PacketConn, error) {
	c, e := NewClient(ctx, config)
	if e != nil {
		return nil, e
	}
	flow, e := c.OpenPacket(ctx, dst)
	if e != nil {
		c.Close()
		return nil, e
	}
	return &privatePacket{PacketConn: flow, client: c}, nil
}
