package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type teardownBarrierConn struct {
	net.Conn
	closing chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *teardownBarrierConn) Close() error {
	c.once.Do(func() { close(c.closing); <-c.release })
	return c.Conn.Close()
}

func TestUDPTeardownRejectsLateAdmission(t *testing.T) {
	x, y := net.Pipe()
	defer y.Close()
	conn := &teardownBarrierConn{Conn: x, closing: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(conn.release) }) }
	defer unblock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &clientSession{}
	m := &udpMux{conn: conn, ctx: ctx, cancel: cancel, s: owner, c: &Client{config: ClientConfig{MaxFlows: 4, UDPIdleTimeout: time.Hour}}, flows: map[netip.AddrPort]*Packet{}, next: 1024}
	owner.udp = m
	target := netip.MustParseAddrPort("192.0.2.29:53")
	first, err := m.open(target)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); m.run() }()
	_ = y.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err = y.Write([]byte{0, 0, 0, 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-conn.closing:
	case <-time.After(time.Second):
		t.Fatal("teardown did not close its stream")
	}
	// Owner close is held in progress; a caller may still retain the old mux.
	late, err := m.open(target)
	if late != nil || !IsCode(err, Framing) {
		t.Fatalf("admission during teardown: packet=%v err=%v", late, err)
	}
	m.mu.Lock()
	retained := len(m.flows)
	m.mu.Unlock()
	if retained != 0 {
		t.Fatalf("retained %d terminal flows", retained)
	}
	unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("teardown workers not joined")
	}
	if _, _, err = first.ReadFrom(make([]byte, 1)); !IsCode(err, Framing) {
		t.Fatalf("child lost terminal reason: %v", err)
	}
	if late, err = m.open(target); late != nil || !IsCode(err, Framing) {
		t.Fatalf("post-teardown admission: %v %v", late, err)
	}
}

func TestUDPMappedTargetContinuity(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			target := udpEcho(t, "udp4", "127.0.0.1:0")
			mapped := netip.AddrPortFrom(netip.AddrFrom16(target.Addr().As16()), target.Port())
			a, tc, _ := startServer(t, mode, nil)
			c := newClient(t, mode, a, tc, nil)
			defer c.Close()
			p, err := c.OpenPacket(context.Background(), mapped)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			_ = p.SetDeadline(time.Now().Add(3 * time.Second))
			for _, destination := range []netip.AddrPort{mapped, target} {
				payload := []byte("mapped IPv4 UDP integrity")
				if _, err = p.WriteTo(payload, net.UDPAddrFromAddrPort(destination)); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, len(payload)+1)
				n, from, err := p.ReadFrom(b)
				if err != nil || from.String() != target.String() || !bytes.Equal(b[:n], payload) {
					t.Fatalf("n=%d from=%v err=%v", n, from, err)
				}
			}
		})
	}
}

func TestUDPInvalidTargetBeforeSessionDial(t *testing.T) {
	// Invalid targets must fail before any session/socket is established.
	c := &Client{config: ClientConfig{DialTCP: func(context.Context, string, string) (net.Conn, error) {
		t.Error("invalid target caused dial")
		return nil, io.EOF
	}}}
	for _, address := range []string{"0.0.0.0:53", "[::ffff:0.0.0.0]:53", "224.0.0.1:53", "[::ffff:224.0.0.1]:53", "[ff02::1]:53", "[fe80::1%eth0]:53", "127.0.0.1:0"} {
		if p, err := c.OpenPacket(context.Background(), netip.MustParseAddrPort(address)); p != nil || !IsCode(err, Config) {
			t.Fatalf("accepted %s: %v %v", address, p, err)
		}
	}
}
