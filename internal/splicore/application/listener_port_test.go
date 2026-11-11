package application_test

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/engine/neterror"
)

type fixtureSocketKey struct {
	network string
	address netip.AddrPort
}

type fixturePortLease struct {
	keys   [2]fixtureSocketKey
	tcp    net.Listener
	udp    net.PacketConn
	closed sync.Once
}

var fixturePorts = struct {
	sync.Mutex
	next   int
	claims map[fixtureSocketKey]*fixturePortLease
}{next: 20000, claims: make(map[fixtureSocketKey]*fixturePortLease)}

// A bare TCP :0 probe cannot promise UDP availability, and its released port
// can immediately be selected by a new API/echo socket. Reserve both objects,
// select outside the kernel's automatic allocation range, and retain the fixture
// assignment until this test ends. Runtime Start still performs the actual bind;
// there is no startup retry or change to production conflict detection.
func availableListenerPort(t *testing.T) uint16 {
	t.Helper()
	first, last := 32768, 65535
	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if _, err := fmt.Sscan(string(data), &first, &last); err != nil {
			t.Fatal(err)
		}
	}
	fixturePorts.Lock()
	defer fixturePorts.Unlock()
	for range 65535 - 1024 {
		port := fixturePorts.next
		fixturePorts.next++
		if fixturePorts.next > 65535 {
			fixturePorts.next = 1024
		}
		if port >= first && port <= last {
			continue
		}
		address := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
		keys := [2]fixtureSocketKey{{network: "tcp4", address: address}, {network: "udp4", address: address}}
		if fixturePorts.claims[keys[0]] != nil || fixturePorts.claims[keys[1]] != nil {
			continue
		}
		tcp, err := net.Listen("tcp4", address.String())
		if err != nil {
			if neterror.AddressInUse(err) {
				continue // This candidate has a known existing TCP owner.
			}
			t.Fatal(err)
		}
		udp, err := net.ListenPacket("udp4", address.String())
		if err != nil {
			_ = tcp.Close()
			if neterror.AddressInUse(err) {
				continue // The TCP object cannot reserve the UDP namespace.
			}
			t.Fatal(err)
		}
		lease := &fixturePortLease{keys: keys, tcp: tcp, udp: udp}
		fixturePorts.claims[keys[0]], fixturePorts.claims[keys[1]] = lease, lease
		t.Cleanup(func() {
			lease.releaseSockets()
			fixturePorts.Lock()
			defer fixturePorts.Unlock()
			for _, key := range lease.keys {
				if fixturePorts.claims[key] == lease {
					delete(fixturePorts.claims, key)
				}
			}
		})
		// Handoff: the next managed command owns the real sockets. The fixture
		// lease prevents this process from allocating this assignment again.
		lease.releaseSockets()
		return uint16(port)
	}
	t.Fatal("no unassigned TCP/UDP fixture endpoint outside the automatic range")
	return 0
}

func (lease *fixturePortLease) releaseSockets() {
	lease.closed.Do(func() {
		_ = lease.tcp.Close()
		_ = lease.udp.Close()
	})
}

func TestListenerPortFixtureKeepsSocketNamespacesAndOwners(t *testing.T) {
	port := availableListenerPort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal("UDP ownership incorrectly excluded TCP", err)
	}
	defer tcp.Close()
	if other, err := net.ListenPacket("udp4", addr); err == nil {
		other.Close()
		t.Fatal("two UDP objects own the same address")
	} else if !neterror.AddressInUse(err) {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			candidate := availableListenerPort(t)
			if candidate == port {
				t.Error("an active assignment was reissued")
			}
		})
	}
	wg.Wait()
}
