package clientruntime

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// DialServerTarget routes authenticated server traffic through the same retained Core
// generation as local and endpoint ingress, without translating its credential
// into a client-side account. The native server retains its own policy/stats.
func (m *Manager) DialServerTarget(ctx context.Context, inbound identity.ID, network, address string, fallback ports.TargetDialer) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, identity.Err(identity.Invalid, "unsupported Core flow network")
	}
	ctx, done, err := m.targetOwner.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	gen := m.acquire()
	if gen == nil {
		return nil, net.ErrClosed
	}
	success := false
	defer func() {
		if !success {
			gen.release()
		}
	}()
	scoped := false
	for _, rule := range gen.state.Network.Route.Rules {
		for _, id := range rule.Match.ServerInbounds {
			if id == inbound {
				scoped = true
			}
		}
	}
	if !scoped {
		raw, err := fallback.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		held := &targetGenerationConn{Conn: raw, generation: gen}
		owned, err := m.targetOwner.Conn(held)
		success = true
		return owned, err
	}
	if !gen.state.Enabled {
		return nil, net.ErrClosed
	}
	ctx = context.WithValue(ctx, serverFlowKey{}, inbound)
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil || number == 0 {
		return nil, identity.Err(identity.Invalid, "invalid Core flow destination")
	}
	decision, resolved, err := selectRouteFallback(ctx, gen, "", access.Endpoint{Host: host, Port: uint16(number)}, network, nil, P.Action{Kind: P.Direct})
	if err != nil {
		return nil, err
	}
	if decision.Selected.Kind == P.Reject {
		return nil, identity.Err(identity.Unavailable, "Core route rejected flow")
	}
	d := gen.outbounds[selectedOutbound(decision.Selected)]
	if d == nil {
		return nil, net.ErrClosed
	}
	var c net.Conn
	if network == "tcp" {
		c, err = d.DialContext(ctx, resolved)
	} else {
		packet, ok := d.(interface {
			ListenPacket(context.Context, access.Endpoint) (net.PacketConn, error)
		})
		if !ok {
			return nil, net.ErrClosed
		}
		var pc net.PacketConn
		pc, err = packet.ListenPacket(ctx, resolved)
		if err == nil {
			c = &targetPacket{PacketConn: pc, target: resolved}
		}
	}
	if err != nil {
		return nil, err
	}
	held := &targetGenerationConn{Conn: c, generation: gen}
	owned, err := m.targetOwner.Conn(held)
	// Owner rejection already closes held and releases the retained generation.
	success = true
	if err != nil {
		return nil, err
	}
	return owned, nil
}

type targetPacket struct {
	net.PacketConn
	target access.Endpoint
}

func (c *targetPacket) RemoteAddr() net.Addr        { return netaddr.UDP(c.target) }
func (c *targetPacket) Read(b []byte) (int, error)  { n, _, err := c.ReadFrom(b); return n, err }
func (c *targetPacket) Write(b []byte) (int, error) { return c.WriteTo(b, c.RemoteAddr()) }

type targetGenerationConn struct {
	net.Conn
	generation *snapshot
	once       sync.Once
	err        error
}

func (c *targetGenerationConn) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close(); c.generation.release() })
	return c.err
}

func (c *targetGenerationConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return c.Close()
}
