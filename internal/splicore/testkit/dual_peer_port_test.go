package testkit

import (
	"net"
	"testing"
)

func TestDualPeerPortLifecycle(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			p := ReserveDualPeerPort(t, host)
			if tcp, err := net.Listen("tcp", p.Address()); err == nil {
				tcp.Close()
				t.Fatal("TCP reservation not held")
			}
			if udp, err := net.ListenPacket("udp", p.Address()); err == nil {
				udp.Close()
				t.Fatal("UDP reservation not held")
			}
			p.ReleaseSockets()
			p.ReleaseSockets()
			tcp, err := net.Listen("tcp", p.Address())
			if err != nil {
				t.Fatal("TCP handoff/rebind", err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp", p.Address())
			if err != nil {
				t.Fatal("UDP handoff/rebind", err)
			}
			defer udp.Close()
		})
	}
}

func TestTCPAvailabilityDoesNotProveUDP(t *testing.T) {
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	if other, err := net.ListenPacket("udp4", tcp.Addr().String()); err == nil {
		other.Close()
		t.Fatal("UDP conflict disappeared despite a successful TCP-only probe")
	}
	t.Logf("original assumption disproved with real sockets: TCP=%s succeeds while UDP is already occupied", tcp.Addr())
}
