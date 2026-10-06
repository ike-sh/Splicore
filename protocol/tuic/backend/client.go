package backend

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

// A managed flow has its own lazy transport, so cancellation and closing a flow
// cannot destroy another flow. No UUID, TLS or scratch bytes cross that boundary.
type ClientConfig struct {
	TLS      *tls.Config
	UUID     [16]byte
	Password string
	Socket   func(context.Context) (net.PacketConn, net.Addr, error)
}
type privateClient struct {
	packet    net.PacketConn
	transport *quic.Transport
	q         *quic.Conn
	writer    *packetio.Writer
	once      sync.Once
}

func (c *privateClient) Close() {
	c.once.Do(func() {
		_ = c.q.CloseWithError(0, "")
		_ = c.transport.Close()
		_ = c.packet.Close()
		c.writer.Wait()
	})
}
func connect(ctx context.Context, config ClientConfig) (*privateClient, error) {
	packet, address, err := config.Socket(ctx)
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: packet}
	tc := config.TLS.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{"h3"}
	q, err := transport.Dial(ctx, address, tc, quicConfig())
	if err != nil {
		_ = transport.Close()
		_ = packet.Close()
		return nil, err
	}
	c := &privateClient{packet: packet, transport: transport, q: q}
	c.writer = packetio.NewWriter(q.Context(), q.SendDatagram)
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	state := q.ConnectionState().TLS
	token, err := state.ExportKeyingMaterial(string(config.UUID[:]), []byte(config.Password), 32)
	if err != nil {
		c.Close()
		return nil, err
	}
	frame, err := wire.AuthFrame(config.UUID, token)
	if err != nil {
		c.Close()
		return nil, err
	}
	auth, err := q.OpenUniStreamSync(ctx)
	if err != nil {
		c.Close()
		return nil, err
	}
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = auth.SetWriteDeadline(deadline)
	if err = wire.Write(auth, frame); err == nil {
		err = auth.Close()
	}
	if err != nil || ctx.Err() != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	return c, nil
}
func OpenTCP(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.Conn, error) {
	frame, err := wire.ConnectFrame(dst)
	if err != nil {
		return nil, err
	}
	c, err := connect(ctx, config)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	stream, err := c.q.OpenStreamSync(ctx)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err = wire.Write(stream, frame); err != nil || ctx.Err() != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return &Stream{Stream: stream, q: c.q, afterClose: c.Close}, nil
}

type clientPacket struct {
	*packetio.Queue
	client      *privateClient
	association uint16
	done        chan struct{}
	once        sync.Once
}

func (p *clientPacket) Close() error {
	p.once.Do(func() {
		_ = p.Queue.Close()
		frame := binary.BigEndian.AppendUint16([]byte{wire.Version, wire.Dissociate}, p.association)
		if s, err := p.client.q.OpenUniStream(); err == nil {
			_ = s.SetWriteDeadline(time.Now().Add(time.Second))
			_ = wire.Write(s, frame)
			_ = s.Close()
		}
		p.client.Close()
		<-p.done
	})
	return nil
}
func OpenPacket(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.PacketConn, error) {
	if dst.Validate() != nil {
		return nil, wire.ErrFrame
	}
	c, err := connect(ctx, config)
	if err != nil {
		return nil, err
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		c.Close()
		return nil, err
	}
	id := binary.BigEndian.Uint16(random[:])
	var sequence atomic.Uint32
	p := &clientPacket{client: c, association: id, done: make(chan struct{})}
	p.Queue = packetio.New(c.q.Context(), c.q.LocalAddr(), func(writeCtx context.Context, b []byte, _ net.Addr) error {
		frames, err := wire.Fragments(id, uint16(sequence.Add(1)), dst, b)
		if err != nil {
			return err
		}
		for _, frame := range frames {
			if writeCtx.Err() != nil {
				return context.Cause(writeCtx)
			}
			if err := c.writer.Send(writeCtx, frame); err != nil {
				return err
			}
		}
		return nil
	})
	go func() {
		defer close(p.done)
		defer p.Queue.Close()
		var assembly wire.Assembly
		for {
			b, err := c.q.ReceiveDatagram(p.Context())
			if err != nil {
				return
			}
			d, err := wire.Decode(b)
			if err != nil || d.Association != id {
				continue
			}
			if d, ok := assembly.Add(d); ok {
				p.Deliver(d.Payload, netaddr.UDP(d.Destination))
			}
		}
	}()
	return p, nil
}
