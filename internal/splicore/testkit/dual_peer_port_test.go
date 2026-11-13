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
	// Own both sockets throughout the counterexample. A bare UDP :0 followed
	// by TCP bind can instead collide with unrelated full-suite TCP clients,
	// failing before the independence assertion is reached.
	lease := ReserveDualPeerPort(t, "127.0.0.1")
	client, err := net.Dial("tcp4", lease.Address())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if other, err := net.ListenPacket("udp4", lease.Address()); err == nil {
		other.Close()
		t.Fatal("UDP conflict disappeared despite a successful TCP-only probe")
	}
	t.Logf("original assumption disproved with owned real sockets: TCP=%s connects while another UDP bind is rejected", lease.Address())
}
