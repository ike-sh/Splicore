//go:build !windows

package xray

import "net"

func reserveClientListeners() (net.Listener, net.PacketConn, error) {
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		return nil, nil, err
	}
	return tcp, udp, nil
}
