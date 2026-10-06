package backend

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

// ClientConfig is immutable. Socket creates a protected numeric underlay for
// each flow, lazily. A canceled handshake closes only that flow's transport.
type ClientConfig struct {
	TLS      *tls.Config
	Password string
	Socket   func(context.Context) (net.PacketConn, net.Addr, error)
}
type privateClient struct {
	packet     net.PacketConn
	transport  *quic.Transport
	control    *http3.Transport
	connection atomic.Pointer[quic.Conn]
	once       sync.Once
	writer     *packetio.Writer
}

func (c *privateClient) Close() {
	c.once.Do(func() {
		if q := c.connection.Load(); q != nil {
			_ = q.CloseWithError(0x100, "")
		}
		_ = c.control.Close()
		_ = c.transport.Close()
		_ = c.packet.Close()
		if c.writer != nil {
			c.writer.Wait()
		}
	})
}
func connect(ctx context.Context, config ClientConfig) (*privateClient, bool, error) {
	packet, address, err := config.Socket(ctx)
	if err != nil {
		return nil, false, err
	}
	c := &privateClient{packet: packet, transport: &quic.Transport{Conn: packet}}
	qc := quicConfig()
	qc.AssumePeerMaxDatagramFrameSize = 0
	qc.OmitMaxDatagramFrameSize = true
	qc.KeepAlivePeriod = 10 * time.Second
	c.control = &http3.Transport{TLSClientConfig: config.TLS.Clone(), QUICConfig: qc, Dial: func(ctx context.Context, _ string, tls *tls.Config, conf *quic.Config) (*quic.Conn, error) {
		conn, err := c.transport.DialEarly(ctx, address, tls, conf)
		if err == nil {
			c.connection.Store(conn)
		}
		return conn, err
	}}
	stop := context.AfterFunc(ctx, func() { _ = packet.Close() })
	defer stop()
	request := (&http.Request{Method: http.MethodPost, URL: &url.URL{Scheme: "https", Host: "hysteria", Path: "/auth"}, Header: make(http.Header)}).WithContext(ctx)
	request.Header.Set("Hysteria-Auth", config.Password)
	request.Header.Set("Hysteria-CC-RX", "0")
	padding, err := wire.Padding(256, 2048)
	if err != nil {
		c.Close()
		return nil, false, err
	}
	request.Header.Set("Hysteria-Padding", padding)
	response, err := c.control.RoundTrip(request)
	if err != nil {
		c.Close()
		return nil, false, err
	}
	_ = response.Body.Close()
	if response.StatusCode != 233 || ctx.Err() != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, false, wire.ErrRejected
	}
	c.writer = packetio.NewWriter(c.connection.Load().Context(), c.connection.Load().SendDatagram)
	return c, response.Header.Get("Hysteria-UDP") == "true", nil
}
func OpenTCP(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.Conn, error) {
	if dst.Validate() != nil {
		return nil, wire.ErrFrame
	}
	c, _, err := connect(ctx, config)
	if err != nil {
		return nil, err
	}
	q := c.connection.Load()
	stream, err := q.OpenStreamSync(ctx)
	if err != nil {
		c.Close()
		return nil, err
	}
	conn := &Stream{Stream: stream, connection: q, afterClose: c.Close}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = stream.SetDeadline(deadline)
	if err = wire.WriteRequest(stream, dst); err == nil {
		err = wire.ReadResponse(stream)
	}
	stop()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return conn, nil
}

type clientPacket struct {
	*Packet
	client *privateClient
	done   chan struct{}
	once   sync.Once
}

func (p *clientPacket) Close() error {
	p.once.Do(func() { _ = p.Packet.Close(); p.client.Close(); <-p.done })
	return nil
}
func OpenPacket(ctx context.Context, config ClientConfig, dst access.Endpoint) (net.PacketConn, error) {
	if dst.Validate() != nil {
		return nil, wire.ErrFrame
	}
	c, udp, err := connect(ctx, config)
	if err != nil {
		return nil, err
	}
	if !udp {
		c.Close()
		return nil, wire.ErrRejected
	}
	var random [4]byte
	if _, err = rand.Read(random[:]); err != nil {
		c.Close()
		return nil, err
	}
	q := c.connection.Load()
	p := &clientPacket{Packet: newPacket(q.Context(), q.LocalAddr(), binary.BigEndian.Uint32(random[:]), c.writer.Send), client: c, done: make(chan struct{})}
	go func() {
		defer close(p.done)
		defer p.Packet.Close()
		var fragments wire.Assembly
		for {
			b, err := q.ReceiveDatagram(p.ctx)
			if err != nil {
				return
			}
			d, err := wire.DecodeDatagram(b)
			if err != nil || d.Session != p.session {
				continue
			}
			if complete, ok := fragments.Add(d); ok {
				p.deliver(complete)
			}
		}
	}()
	return &DefaultPacket{PacketConn: p, Destination: dst}, nil
}
