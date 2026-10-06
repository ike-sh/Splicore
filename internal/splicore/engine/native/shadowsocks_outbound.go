package native

import (
	"context"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type ShadowsocksOutboundFactory struct{}

func (ShadowsocksOutboundFactory) Capability() ports.OutboundCapability {
	return clientconfig.Capability("shadowsocks", false, false, false)
}
func (ShadowsocksOutboundFactory) Validate(n client.RemoteNode, c access.Credential) error {
	if e := clientconfig.Ownership(n, c); e != nil {
		return e
	}
	options, e := module.DecodeClient(n.Options.Data)
	if e != nil {
		return e
	}
	m, _ := module.Lookup(options.Method)
	if n.Protocol != module.Key(m.Edition) || n.Transport.Kind != "tcp" || n.Security.Kind != "none" || c.Validate() != nil || c.State != "active" {
		return identity.Err(identity.Invalid, "invalid shadowsocks node")
	}
	return module.ValidateMaterial(options.Method, c.Payload, true)
}
func (f ShadowsocksOutboundFactory) Build(ctx context.Context, n client.RemoteNode, c access.Credential) (ports.ClientDialer, error) {
	if e := f.Validate(n, c); e != nil {
		return nil, e
	}
	protected, e := underlay.DialerFrom(ctx, underlay.PurposeFrom(ctx, underlay.ProxyUnderlay))
	if e != nil {
		return nil, e
	}
	o, _ := module.DecodeClient(n.Options.Data)
	keys, e := wire.Keys(o.Method, module.Material(c.Payload))
	if e != nil {
		return nil, e
	}
	return &shadowsocksDialer{protected: protected, endpoint: n.Endpoint, keys: keys, udp: o.UDP, owner: clientio.New(), replay: wire.NewSaltCache(8192, 5*time.Minute)}, nil
}

type shadowsocksDialer struct {
	protected *underlay.Dialer
	endpoint  access.Endpoint
	keys      []*wire.Key
	udp       bool
	owner     *clientio.Owner
	replay    *wire.SaltCache
}

func (d *shadowsocksDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	raw, e := d.protected.DialContext(ctx, "tcp", net.JoinHostPort(d.endpoint.Host, portString(d.endpoint.Port)))
	if e != nil {
		return nil, e
	}
	// Cancellation can interrupt the initial header write; ownership starts before
	// the handshake, so shutdown also closes pending dials.
	raw, e = d.owner.Conn(raw)
	if e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	c, e := wire.ClientTCP(raw, d.keys, dst, d.replay)
	if e != nil {
		raw.Close()
		return nil, identity.Err(identity.Unavailable, "shadowsocks handshake failed")
	}
	_ = raw.SetDeadline(time.Time{})
	return c, nil
}
func (d *shadowsocksDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	if !d.udp {
		return nil, identity.Err(identity.NotImplemented, "shadowsocks UDP disabled")
	}
	if e := dst.Validate(); e != nil {
		return nil, e
	}
	ctx, done, e := d.owner.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer done()
	raw, e := d.protected.DialContext(ctx, "udp", net.JoinHostPort(d.endpoint.Host, portString(d.endpoint.Port)))
	if e != nil {
		return nil, e
	}
	raw, e = d.owner.Conn(raw)
	if e != nil {
		return nil, e
	}
	session, e := wire.SessionID()
	if e != nil {
		raw.Close()
		return nil, e
	}
	return &shadowsocksClientPacket{Conn: raw, target: dst, keys: d.keys, session: session, replay: d.replay, servers: map[uint64]*shadowsocksServerWindow{}}, nil
}
func (d *shadowsocksDialer) Close() error { d.owner.Close(); return nil }

type shadowsocksServerWindow struct {
	window wire.Window
	last   time.Time
}
type shadowsocksClientPacket struct {
	net.Conn
	target           access.Endpoint
	keys             []*wire.Key
	session, counter uint64
	replay           *wire.SaltCache
	rmu, wmu         sync.Mutex
	servers          map[uint64]*shadowsocksServerWindow
}

func (c *shadowsocksClientPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.counter == math.MaxUint64 {
		return 0, wire.ErrCapacity
	}
	dst := c.target
	if a != nil {
		var err error
		dst, err = netaddr.From(a)
		if err != nil {
			return 0, err
		}
	}
	p, e := wire.EncodePacket(c.keys, wire.Datagram{Session: c.session, Packet: c.counter, Destination: dst, Payload: b}, false, time.Now())
	if e != nil {
		return 0, e
	}
	key := c.keys[len(c.keys)-1]
	if key.Method.Edition == "2017" {
		if e = c.replay.Check(key, p[:key.Method.KeySize], time.Now()); e != nil {
			return 0, e
		}
	}
	c.counter++
	n, e := c.Conn.Write(p)
	if e != nil {
		return 0, e
	}
	if n != len(p) {
		return 0, wire.ErrFrame
	}
	return len(b), nil
}
func (c *shadowsocksClientPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	buffer := make([]byte, 65535)
	for rejected := 0; rejected < 64; rejected++ {
		n, e := c.Conn.Read(buffer)
		if e != nil {
			return 0, nil, e
		}
		now := time.Now()
		key := c.keys[len(c.keys)-1]
		p, e := wire.DecodePacket([]*wire.Key{key}, nil, buffer[:n], true, c.session, c.replay, now)
		if e != nil {
			continue
		}
		if key.Method.Edition == "2022" {
			state := c.servers[p.Session]
			if state == nil {
				for id, s := range c.servers {
					if now.Sub(s.last) > 90*time.Second {
						delete(c.servers, id)
					}
				}
				if len(c.servers) >= 128 {
					continue
				}
				state = &shadowsocksServerWindow{}
				c.servers[p.Session] = state
			}
			if !state.window.Accept(p.Packet) {
				continue
			}
			state.window.Commit(p.Packet)
			state.last = now
		}
		if len(p.Payload) > len(b) {
			return 0, nil, wire.ErrFrame
		}
		return copy(b, p.Payload), netaddr.UDP(p.Destination), nil
	}
	return 0, nil, os.ErrInvalid
}
