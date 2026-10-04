package xray

import (
	"errors"
	"net"
	"testing"
)

func TestWindowsPairedReservationClosesRejectedCandidate(t *testing.T) {
	var rejected net.PacketConn
	calls := 0
	listen := func(network, address string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return nil, &net.OpError{Op: "listen", Net: network, Err: windowsAddressInUse}
		}
		return net.Listen(network, address)
	}
	packet := func(network, address string) (net.PacketConn, error) {
		c, err := net.ListenPacket(network, address)
		if calls == 0 {
			rejected = c
		}
		return c, err
	}
	tcp, udp, err := reserveWindowsClientListeners(listen, packet)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	if tcp.Addr().String() != udp.LocalAddr().String() {
		t.Fatal("unpaired reservation")
	}
	if _, err = rejected.WriteTo([]byte("closed"), udp.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("rejected candidate socket retained", err)
	}
	denied := errors.New("fixture policy failure")
	calls = 0
	_, _, err = reserveWindowsClientListeners(func(string, string) (net.Listener, error) { calls++; return nil, denied }, net.ListenPacket)
	if !errors.Is(err, denied) || calls != 1 {
		t.Fatal("non-collision failure was retried", calls, err)
	}
}

func TestWindowsKernelPairedReservations(t *testing.T) {
	held, availableUDP, err := reserveClientListeners()
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	_ = availableUDP.Close()
	first := true
	packet := func(network, address string) (net.PacketConn, error) {
		if first {
			first = false
			address = held.Addr().String()
		}
		return net.ListenPacket(network, address)
	}
	tcp, udp, err := reserveWindowsClientListeners(func(network, address string) (net.Listener, error) {
		c, e := net.Listen(network, address)
		if e != nil {
			t.Logf("occupied TCP candidate: %v", e)
		}
		return c, e
	}, packet)
	if err != nil {
		t.Fatal(err)
	}
	_ = tcp.Close()
	_ = udp.Close()
	for range 64 {
		tcp, udp, err := reserveWindowsClientListeners(func(network, address string) (net.Listener, error) {
			c, e := net.Listen(network, address)
			if e != nil {
				t.Logf("kernel candidate: %v", e)
			}
			return c, e
		}, net.ListenPacket)
		if err != nil {
			t.Fatal(err)
		}
		_ = tcp.Close()
		_ = udp.Close()
	}
}

func TestWindowsExcludedCandidateUsesOtherAllocator(t *testing.T) {
	var rejected net.PacketConn
	calls := 0
	listen := func(network, address string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return nil, &net.OpError{Op: "listen", Net: network, Err: windowsAddressUnavailable}
		}
		if address != "127.0.0.1:0" {
			t.Fatal("allocator did not switch", address)
		}
		return net.Listen(network, address)
	}
	packet := func(network, address string) (net.PacketConn, error) {
		// This test injects one exclusion and checks the allocator transition.
		// Kernel paired-reservation stress has its own test above. A real second
		// UDP bind here can encounter another exclusion and invalidate the single
		// injected-error premise, depending on concurrent kernel port allocation.
		c, err := net.ListenPacket(network, "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		if address != "127.0.0.1:0" {
			a, e := net.ResolveUDPAddr(network, address)
			if e != nil {
				c.Close()
				return nil, e
			}
			c = &reportedPacketAddress{PacketConn: c, address: a}
		}
		if calls == 0 {
			rejected = c
		}
		return c, err
	}
	tcp, udp, err := reserveWindowsClientListeners(listen, packet)
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	defer udp.Close()
	if tcp.Addr().String() != udp.LocalAddr().String() || calls != 2 {
		t.Fatal("unpaired reservation", calls)
	}
	if _, err = rejected.WriteTo([]byte("closed"), udp.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("excluded candidate retained", err)
	}
}

type reportedPacketAddress struct {
	net.PacketConn
	address net.Addr
}

func (c *reportedPacketAddress) LocalAddr() net.Addr { return c.address }
