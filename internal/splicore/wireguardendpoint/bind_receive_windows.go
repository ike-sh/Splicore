package wireguardendpoint

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

func wrapUDPReceiveConn(socket net.PacketConn) net.PacketConn {
	return &udpReceiveConn{PacketConn: socket}
}

type udpReceiveConn struct{ net.PacketConn }

func (c *udpReceiveConn) ReadFrom(packet []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(packet)
		if !errors.Is(err, windows.WSAEMSGSIZE) {
			return n, addr, err
		}
		// Winsock consumed this oversized datagram. Discard its partial bytes
		// and wait on the same socket; returning this non-temporary error would
		// stop WireGuard's receive worker. All other errors retain their semantics.
	}
}
