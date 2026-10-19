package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Raw echo forwarding uses the existing protected socket owner. Fixed mux
// workers bound concurrent sockets; each request owns and closes its socket.
// Failure to obtain raw privileges is explicit; there is no escalation path.
func trustTunnelEcho(protected *underlay.Dialer) session.EchoBackend {
	return func(ctx context.Context, _ string, r wire.EchoRequest) (wire.EchoReply, error) {
		ip := r.Destination.Unmap()
		network, local, protocol := "ip4:icmp", "0.0.0.0", 1
		var kind icmp.Type = ipv4.ICMPTypeEcho
		if ip.Is6() {
			network, local, protocol = "ip6:ipv6-icmp", "::", 58
			kind = ipv6.ICMPTypeEchoRequest
		}
		socket, e := protected.ListenPacket(ctx, network, local, ip.String())
		if e != nil {
			return wire.EchoReply{}, identity.Err(identity.Unavailable, "TrustTunnel raw ICMP socket unavailable; host privileges required")
		}
		defer socket.Close()
		stop := context.AfterFunc(ctx, func() { _ = socket.Close() })
		defer stop()
		if ip.Is4() {
			e = ipv4.NewPacketConn(socket).SetTTL(int(r.TTL))
		} else {
			e = ipv6.NewPacketConn(socket).SetHopLimit(int(r.TTL))
		}
		if e != nil {
			return wire.EchoReply{}, identity.Err(identity.Unavailable, "TrustTunnel ICMP hop limit unavailable")
		}
		var token [4]byte
		if _, e = rand.Read(token[:]); e != nil {
			return wire.EchoReply{}, e
		}
		id, seq := int(binary.BigEndian.Uint16(token[:2])), int(binary.BigEndian.Uint16(token[2:]))
		data := make([]byte, int(r.DataSize))
		if _, e = rand.Read(data); e != nil {
			return wire.EchoReply{}, e
		}
		message := icmp.Message{Type: kind, Body: &icmp.Echo{ID: id, Seq: seq, Data: data}}
		b, e := message.Marshal(nil)
		if e != nil {
			return wire.EchoReply{}, e
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(3 * time.Second)
		}
		_ = socket.SetDeadline(deadline)
		if _, e = socket.WriteTo(b, &net.IPAddr{IP: net.IP(ip.AsSlice())}); e != nil {
			return wire.EchoReply{}, e
		}
		buffer := make([]byte, 65535)
		for {
			n, from, e := socket.ReadFrom(buffer)
			if e != nil {
				return wire.EchoReply{}, e
			}
			source, ok := netip.AddrFromSlice(from.(*net.IPAddr).IP)
			if !ok || source.Unmap() != ip {
				continue
			}
			parsed, e := icmp.ParseMessage(protocol, buffer[:n])
			if e != nil || parsed.Code != 0 {
				continue
			}
			if ip.Is4() && parsed.Type != ipv4.ICMPTypeEchoReply || ip.Is6() && parsed.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
			echo, ok := parsed.Body.(*icmp.Echo)
			if !ok || echo.ID != id || echo.Seq != seq || !bytes.Equal(echo.Data, data) {
				continue
			}
			replyType := uint8(0)
			if ip.Is6() {
				replyType = 129
			}
			return wire.EchoReply{ID: r.ID, Source: ip, Type: replyType, Sequence: r.Sequence}, nil
		}
	}
}
