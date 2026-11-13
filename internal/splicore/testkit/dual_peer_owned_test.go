package testkit

import (
	"net"
	"os"
	"testing"
)

func TestDualPeerPortOwnedSocketLifetime(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			pair := ReserveDualPeerPort(t, host)
			tcp, udp := pair.OwnedSockets()
			if tcp == nil || udp == nil || tcp.Addr().String() != pair.Address() || udp.LocalAddr().String() != pair.Address() {
				t.Fatal("retained pair does not own the same TCP/UDP endpoint")
			}
			VerifyDualPeerProcess(t, os.Getpid(), pair.Address())
			if other, err := net.Listen("tcp", pair.Address()); err == nil {
				other.Close()
				t.Fatal("live TCP ownership was lost")
			}
			if other, err := net.ListenPacket("udp", pair.Address()); err == nil {
				other.Close()
				t.Fatal("live UDP ownership was lost")
			}
			pair.ReleaseSockets()
			againTCP, err := net.Listen("tcp", pair.Address())
			if err != nil {
				t.Fatal("released TCP endpoint cannot be rebound", err)
			}
			t.Cleanup(func() { againTCP.Close() })
			againUDP, err := net.ListenPacket("udp", pair.Address())
			if err != nil {
				t.Fatal("released UDP endpoint cannot be rebound", err)
			}
			t.Cleanup(func() { againUDP.Close() })
		})
	}
}
