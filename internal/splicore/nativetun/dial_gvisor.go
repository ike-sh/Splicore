//go:build with_gvisor

package nativetun

import (
	"context"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func networkAddress(ip netip.Addr, port uint16) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	protocol := header.IPv4ProtocolNumber
	if ip.Is6() {
		protocol = header.IPv6ProtocolNumber
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: port}, protocol
}

func (b *gvisorBackend) dialTCP(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	ctx, done, err := b.outbound.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	addr, protocol := networkAddress(remote.Addr(), remote.Port())
	bind, _ := networkAddress(local, 0)
	c, err := gonet.DialTCPWithBind(ctx, b.stack, bind, addr, protocol)
	if err != nil {
		return nil, err
	}
	return b.outbound.Conn(c)
}

func (b *gvisorBackend) listenUDP(ctx context.Context, local netip.Addr) (net.PacketConn, error) {
	_, done, err := b.outbound.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	bind, protocol := networkAddress(local, 0)
	c, err := gonet.DialUDP(b.stack, &bind, nil, protocol)
	if err != nil {
		return nil, err
	}
	return b.outbound.Packet(c)
}
