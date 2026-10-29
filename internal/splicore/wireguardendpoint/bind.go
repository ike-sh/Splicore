package wireguardendpoint

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"golang.zx2c4.com/wireguard/conn"
)

type udpEndpoint struct{ address netip.AddrPort }

func (e *udpEndpoint) ClearSrc()           {}
func (e *udpEndpoint) SrcToString() string { return "" }
func (e *udpEndpoint) DstToString() string { return e.address.String() }
func (e *udpEndpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *udpEndpoint) DstToBytes() []byte {
	b := e.address.Addr().AsSlice()
	return binary.BigEndian.AppendUint16(append([]byte(nil), b...), e.address.Port())
}

// udpBind owns one dual-stack UDP socket. The receive closure captures that
// exact socket; reopening cannot redirect an old reader to a new socket.
type udpBind struct {
	mu        sync.Mutex
	protected *underlay.Dialer
	ctx       context.Context
	socket    net.PacketConn
}

func (b *udpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	socket, err := b.protected.ListenPacket(b.ctx, "udp", net.JoinHostPort("::", strconv.Itoa(int(port))), "")
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	actual := uint16(socket.LocalAddr().(*net.UDPAddr).Port)
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		n, addr, err := socket.ReadFrom(packets[0])
		if err != nil {
			return 0, err
		}
		source := addr.(*net.UDPAddr).AddrPort()
		source = netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
		sizes[0] = n
		endpoints[0] = &udpEndpoint{source}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, actual, nil
}

func (b *udpBind) Close() error {
	b.mu.Lock()
	socket := b.socket
	b.socket = nil
	b.mu.Unlock()
	if socket != nil {
		return socket.Close()
	}
	return nil
}

func (b *udpBind) SetMark(mark uint32) error {
	if mark != 0 {
		return net.InvalidAddrError("WireGuard socket marks are not configured")
	}
	return nil
}
func (b *udpBind) BatchSize() int { return 1 }
func (b *udpBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &udpEndpoint{address}, nil
}

func (b *udpBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	e, ok := endpoint.(*udpEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, packet := range bufs {
		if _, err := socket.WriteTo(packet, net.UDPAddrFromAddrPort(e.address)); err != nil {
			return err
		}
	}
	return nil
}

func (b *udpBind) resources() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return 1
	}
	return 0
}
