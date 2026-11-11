//go:build with_quic

package streamtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
)

type PacketSocket func(context.Context) (net.PacketConn, net.Addr, error)

func genericQUICConfig(server bool) *quic.Config {
	incoming := int64(-1)
	if server {
		incoming = 128
	}
	return &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: incoming, MaxIncomingUniStreams: -1, InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 256 << 10, InitialConnectionReceiveWindow: 512 << 10, MaxConnectionReceiveWindow: 2 << 20, Allow0RTT: false, EnableDatagrams: false}
}

func genericQUICTLS(tc *tls.Config, c cfg.Config, server bool) (*tls.Config, error) {
	if tc == nil || c.Type() != "quic-stream" || c.Validate() != nil || c.ValidateALPN(tc.NextProtos) != nil || !server && tc.ServerName == "" {
		return nil, errNativeConfig
	}
	tc = tc.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{cfg.GenericQUICALPN}
	tc.SessionTicketsDisabled = true
	tc.ClientSessionCache = nil
	return tc, nil
}

type quicStreamConn struct {
	*quic.Stream
	connection  *quic.Conn
	once        sync.Once
	release     func()
	writeMu     sync.Mutex
	stateMu     sync.Mutex
	writing     bool
	closed      bool
	writeClosed bool
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.connection.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.connection.RemoteAddr() }

func (c *quicStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.stateMu.Lock()
	if c.closed || c.writeClosed {
		e := error(io.ErrClosedPipe)
		if c.closed {
			e = net.ErrClosed
		}
		c.stateMu.Unlock()
		return 0, e
	}
	c.writing = true
	c.stateMu.Unlock()
	n, e := c.Stream.Write(p)
	c.stateMu.Lock()
	c.writing = false
	c.stateMu.Unlock()
	return n, e
}

func (c *quicStreamConn) CloseWrite() error {
	// quic-go requires FIN to be serialized with Write. Full Close never
	// takes writeMu, so it can interrupt a writer waiting for flow control.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return c.Stream.Close()
}

func (c *quicStreamConn) Close() error {
	c.once.Do(func() {
		c.stateMu.Lock()
		c.closed = true
		c.Stream.CancelRead(1)
		if c.writing {
			// FIN does not wake a pending Write. Reset only this stream's
			// send direction; the shared connection remains reusable.
			c.Stream.CancelWrite(1)
		} else if !c.writeClosed {
			// Preserve reliable delivery of bytes accepted by completed
			// writes. No new Write can enter after closed is published.
			_ = c.Stream.Close()
		}
		c.stateMu.Unlock()
		c.release()
	})
	return nil
}

type quicNativeClient struct {
	sessions  sync.WaitGroup
	workers   sync.WaitGroup
	tls       *tls.Config
	socket    PacketSocket
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	dialMu    sync.Mutex
	conn      *quic.Conn
	transport *quic.Transport
	packet    net.PacketConn
	streams   map[*quicStreamConn]bool
	pending   int
	once      sync.Once
}

func NewPacketClient(socket PacketSocket, c cfg.Config, tc *tls.Config) (*Client, error) {
	tc, e := genericQUICTLS(tc, c, false)
	if e != nil || socket == nil {
		return nil, errNativeConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{impl: &quicNativeClient{tls: tc, socket: socket, ctx: ctx, cancel: cancel, streams: map[*quicStreamConn]bool{}}}, nil
}

func (c *quicNativeClient) connection(ctx context.Context) (*quic.Conn, error) {
	c.dialMu.Lock()
	defer c.dialMu.Unlock()
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	q := c.conn
	if q != nil && q.Context().Err() == nil {
		c.mu.Unlock()
		return q, nil
	}
	oldTransport, oldPacket := c.transport, c.packet
	c.conn = nil
	c.transport = nil
	c.packet = nil
	c.mu.Unlock()
	if oldTransport != nil {
		oldTransport.Close()
	}
	if oldPacket != nil {
		oldPacket.Close()
	}
	admission, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	p, peer, e := c.socket(admission)
	if e != nil {
		return nil, e
	}
	if p == nil || peer == nil {
		if p != nil {
			p.Close()
		}
		return nil, errNativeConfig
	}
	tr := &quic.Transport{Conn: p}
	q, e = tr.Dial(admission, peer, c.tls, genericQUICConfig(false))
	if e != nil {
		tr.Close()
		p.Close()
		return nil, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx.Err() != nil {
		q.CloseWithError(0, "closed")
		tr.Close()
		p.Close()
		return nil, net.ErrClosed
	}
	c.conn = q
	c.transport = tr
	c.packet = p
	c.sessions.Go(func() {
		<-q.Context().Done()
		c.mu.Lock()
		if c.conn == q {
			c.conn = nil
			c.transport = nil
			c.packet = nil
		}
		c.mu.Unlock()
		tr.Close()
		p.Close()
	})
	return q, nil
}

func (c *quicNativeClient) DialContext(ctx context.Context) (net.Conn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c.mu.Lock()
	if c.ctx.Err() != nil || c.pending+len(c.streams) >= 128 {
		c.mu.Unlock()
		return nil, errors.New("QUIC transport closed or stream limit reached")
	}
	c.pending++
	c.workers.Add(1)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.pending--; c.mu.Unlock(); c.workers.Done() }()
	q, e := c.connection(ctx)
	if e != nil {
		return nil, e
	}
	admission, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	s, e := q.OpenStreamSync(admission)
	if e != nil {
		return nil, e
	}
	var stream *quicStreamConn
	stream = &quicStreamConn{Stream: s, connection: q, release: func() { c.mu.Lock(); delete(c.streams, stream); c.mu.Unlock() }}
	c.mu.Lock()
	if c.ctx.Err() != nil || ctx.Err() != nil {
		c.mu.Unlock()
		stream.Close()
		return nil, net.ErrClosed
	}
	c.streams[stream] = true
	c.mu.Unlock()
	return stream, nil
}

func (c *quicNativeClient) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.dialMu.Lock()

		c.mu.Lock()
		q, tr, p := c.conn, c.transport, c.packet
		ss := make([]*quicStreamConn, 0, len(c.streams))
		for s := range c.streams {
			ss = append(ss, s)
		}
		c.mu.Unlock()
		for _, s := range ss {
			s.Close()
		}
		if q != nil {
			q.CloseWithError(0, "closed")
		}
		if tr != nil {
			tr.Close()
		}
		if p != nil {
			p.Close()
		}
		c.dialMu.Unlock()
		c.workers.Wait()
		c.sessions.Wait()
	})
	return nil
}

type quicNativeListener struct {
	packet    net.PacketConn
	transport *quic.Transport
	listener  *quic.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	conns     map[*quic.Conn]bool
	queue     chan net.Conn
	workers   sync.WaitGroup
	once      sync.Once
}

func newQUICListener(p net.PacketConn, c cfg.Config, tc *tls.Config) (net.Listener, error) {
	tc, e := genericQUICTLS(tc, c, true)
	if e != nil || p == nil || len(tc.Certificates) == 0 && tc.GetCertificate == nil {
		return nil, errNativeConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &quicNativeListener{packet: p, ctx: ctx, cancel: cancel, conns: map[*quic.Conn]bool{}, queue: make(chan net.Conn, 64)}
	slots := make(chan struct{}, 128)
	l.transport = &quic.Transport{Conn: p, VerifySourceAddress: func(net.Addr) bool { return true }, ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
		select {
		case slots <- struct{}{}:
			context.AfterFunc(ctx, func() { <-slots })
			return ctx, nil
		default:
			return nil, errors.New("connection limit")
		}
	}}
	l.listener, e = l.transport.Listen(tc, genericQUICConfig(true))
	if e != nil {
		cancel()
		l.transport.Close()
		return nil, e
	}
	l.workers.Add(1)
	go l.acceptConnections()
	return l, nil
}

func (l *quicNativeListener) acceptConnections() {
	defer l.workers.Done()
	for {
		q, e := l.listener.Accept(l.ctx)
		if e != nil {
			return
		}
		l.mu.Lock()
		if l.ctx.Err() != nil {
			l.mu.Unlock()
			q.CloseWithError(0, "closed")
			return
		}
		l.conns[q] = true
		l.workers.Add(1)
		l.mu.Unlock()
		go l.acceptStreams(q)
	}
}

func (l *quicNativeListener) acceptStreams(q *quic.Conn) {
	defer l.workers.Done()
	defer func() { q.CloseWithError(0, "closed"); l.mu.Lock(); delete(l.conns, q); l.mu.Unlock() }()
	for {
		s, e := q.AcceptStream(l.ctx)
		if e != nil {
			return
		}
		stream := &quicStreamConn{Stream: s, connection: q, release: func() {}}
		select {
		case l.queue <- stream:
		case <-l.ctx.Done():
			stream.Close()
			return
		default:
			stream.Close()
		}
	}
}

func (l *quicNativeListener) Accept() (net.Conn, error) {
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
func (l *quicNativeListener) Addr() net.Addr { return l.packet.LocalAddr() }
func (l *quicNativeListener) Close() error {
	l.once.Do(func() {
		l.cancel()
		l.listener.Close()
		l.mu.Lock()
		for q := range l.conns {
			q.CloseWithError(0, "closed")
		}
		l.mu.Unlock()
		l.transport.Close()
		l.packet.Close()
		l.workers.Wait()
		for {
			select {
			case c := <-l.queue:
				c.Close()
			default:
				return
			}
		}
	})
	return nil
}
