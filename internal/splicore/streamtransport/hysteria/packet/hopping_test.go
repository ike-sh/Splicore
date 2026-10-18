package packet

import (
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHoppingSelectionConcurrentWritesClose(t *testing.T) {
	raw := &capture{}
	p, logical, e := Hop(raw, peer, &cfg.HysteriaUDP{Ports: "1,65534-65535", HopInterval: 5})
	if e != nil {
		t.Fatal(e)
	}
	c := p.(*Hopping)
	if c.current != 1 && c.current != 65534 && c.current != 65535 {
		t.Fatal("initial")
	}
	first := c.current
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				if _, e := c.WriteTo([]byte{1, 2}, logical); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	if _, e := c.WriteTo([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}); e == nil {
		t.Fatal("unrelated peer accepted")
	}
	until := time.Now().Add(6 * time.Second)
	stopWrites := make(chan struct{})
	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopWrites:
				return
			case <-ticker.C:
				_, _ = c.WriteTo([]byte{1}, logical)
			}
		}
	}()
	for {
		c.mu.Lock()
		port := c.current
		c.mu.Unlock()
		if port != first {
			break
		}
		if time.Now().After(until) {
			t.Fatal("no scheduled hop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stopWrites)
	<-writeDone
	c.Close()
	if _, e := c.WriteTo([]byte{1}, logical); e != net.ErrClosed {
		t.Fatal("write after close", e)
	}
	select {
	case <-c.exited:
	default:
		t.Fatal("scheduler not joined")
	}
	c.Close()
	for _, d := range raw.out {
		if a := d.a.(*net.UDPAddr); (a.Port != 1 && a.Port != 65534 && a.Port != 65535) || !a.IP.Equal(peer.IP) {
			t.Fatal("physical peer")
		}
	}
}
func TestHoppingNormalizeAllowedPortsAndDeadlines(t *testing.T) {
	receiver, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	good, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer good.Close()
	bad, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer bad.Close()
	ports := good.LocalAddr().(*net.UDPAddr).Port
	u := &cfg.HysteriaUDP{Ports: fmtPort(ports)}
	p, logical, e := Hop(receiver, peer, u)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	select {
	case <-p.(*Hopping).exited:
	default:
		t.Fatal("single-port scheduler")
	}
	p.SetReadDeadline(time.Now().Add(time.Second))
	bad.WriteTo([]byte{9}, receiver.LocalAddr())
	good.WriteTo([]byte{7}, receiver.LocalAddr())
	b := make([]byte, 16)
	n, a, e := p.ReadFrom(b)
	if e != nil || n != 1 || b[0] != 7 || a.String() != logical.String() {
		t.Fatal(n, a, e)
	}
	p.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	if _, _, e = p.ReadFrom(b); e == nil {
		t.Fatal("deadline lost")
	}
}
func fmtPort(n int) string {
	a := &net.UDPAddr{Port: n}
	_, p, _ := net.SplitHostPort(a.String())
	return p
}

func TestGeckoReassemblyAcrossPhysicalHopPorts(t *testing.T) {
	raw, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	senders := make([]net.PacketConn, 2)
	ports := ""
	for i := range senders {
		senders[i], e = net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer senders[i].Close()
		if i > 0 {
			ports += ","
		}
		ports += fmtPort(senders[i].LocalAddr().(*net.UDPAddr).Port)
	}
	hopped, _, e := Hop(raw, peer, &cfg.HysteriaUDP{Ports: ports})
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := Wrap(hopped, &cfg.HysteriaObfs{Type: "gecko", Password: "SyntheticHopGecko"})
	if e != nil {
		hopped.Close()
		t.Fatal(e)
	}
	defer receiver.Close()
	receiver.SetReadDeadline(time.Now().Add(time.Second))
	for i := range 2 {
		wire, e := encode("SyntheticHopGecko", frame(1, byte(i), 2, 0, []byte{0xC0, byte(i)}))
		if e != nil {
			t.Fatal(e)
		}
		senders[i].WriteTo(wire, raw.LocalAddr())
	}
	b := make([]byte, 16)
	n, a, e := receiver.ReadFrom(b)
	if e != nil || n != 4 || a.String() != peer.String() || b[1] != 0 || b[3] != 1 {
		t.Fatal("fragments keyed by physical port", n, a, e)
	}
}

func TestHoppingIPv6OwnedPorts(t *testing.T) {
	var peers []net.PacketConn
	var ports []string
	for range 2 {
		p, e := net.ListenPacket("udp6", "[::1]:0")
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		peers = append(peers, p)
		ports = append(ports, strconv.Itoa(p.LocalAddr().(*net.UDPAddr).Port))
	}
	raw, e := net.ListenPacket("udp6", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	p, logical, e := Hop(Own(raw), peers[0].LocalAddr(), &cfg.HysteriaUDP{Ports: strings.Join(ports, ",")})
	if e != nil {
		raw.Close()
		t.Fatal(e)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(2 * time.Second))
	var wg sync.WaitGroup
	for _, server := range peers {
		server.SetDeadline(time.Now().Add(time.Second))
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 32)
			n, a, e := server.ReadFrom(b)
			if e == nil {
				server.WriteTo(b[:n], a)
			}
		}()
	}
	if _, e = p.WriteTo([]byte("IPv6"), logical); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 32)
	n, a, e := p.ReadFrom(b)
	if e != nil || string(b[:n]) != "IPv6" || a.String() != logical.String() {
		t.Fatal("IPv6 logical peer", n, a, e)
	}
	wg.Wait()
}
