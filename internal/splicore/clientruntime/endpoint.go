package clientruntime

import (
	"context"
	"net"
	"net/netip"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// ConfigureEndpoints is initialization-only, before publishing a generation.
// Endpoint adapters are borrowed from the Application Service's registry.
func (m *Manager) ConfigureEndpoints(lookup func(string) (ports.ClientDialer, error)) {
	m.endpointLookup = lookup
}

func (m *Manager) endpointIngress(tag string) (*tunIngress, *snapshot) {
	gen := m.acquire()
	if gen == nil {
		return nil, nil
	}
	if !gen.state.Enabled {
		gen.release()
		return nil, nil
	}
	for _, spec := range gen.state.LocalInbounds {
		if spec.Kind == "endpoint" && spec.EndpointTag == tag {
			return &tunIngress{manager: m, spec: spec, staged: gen}, gen
		}
	}
	gen.release()
	return nil, nil
}

// EndpointTCP/UDP use the same session, routing, DNS, policy and relay path as
// native IP ingress. No authenticated peer is converted to a server account.
func (m *Manager) EndpointTCP(ctx context.Context, tag string, c net.Conn, source, destination netip.AddrPort) {
	ingress, gen := m.endpointIngress(tag)
	if ingress == nil {
		_ = c.Close()
		return
	}
	defer gen.release()
	ingress.TCP(ctx, c, source, destination)
}

func (m *Manager) EndpointUDP(ctx context.Context, tag string, c net.Conn, source, destination netip.AddrPort) {
	ingress, gen := m.endpointIngress(tag)
	if ingress == nil {
		_ = c.Close()
		return
	}
	defer gen.release()
	ingress.UDP(ctx, c, source, destination)
}

// BorrowedEndpoint never closes its provider's Device. Snapshot/session owners
// still close their own connections and packet associations normally.
type BorrowedEndpoint struct {
	Lookup func() (ports.ClientDialer, error)
}

func (d BorrowedEndpoint) DialContext(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	p, err := d.Lookup()
	if err != nil {
		return nil, err
	}
	return p.DialContext(ctx, target)
}

func (d BorrowedEndpoint) ListenPacket(ctx context.Context, target access.Endpoint) (net.PacketConn, error) {
	p, err := d.Lookup()
	if err != nil {
		return nil, err
	}
	packet, ok := p.(ports.ClientPacketDialer)
	if !ok {
		return nil, net.ErrClosed
	}
	return packet.ListenPacket(ctx, target)
}

func (d BorrowedEndpoint) SupportsNetwork(network string) bool {
	return network == "tcp" || network == "udp"
}
func (d BorrowedEndpoint) Close() error { return nil }
