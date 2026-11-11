//go:build !windows

package wireguardendpoint

import "net"

func wrapUDPReceiveConn(socket net.PacketConn) net.PacketConn { return socket }
