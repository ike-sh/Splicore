package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func listenSOCKS5UDPTest(t *testing.T, host string) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func startSOCKS5UDPTest(t *testing.T, ctx context.Context, host, options string, allowed *atomic.Bool, idle, flowIdle time.Duration) (*socks5Handle, *socks5.Credentials) {
	t.Helper()
	intent := socks5Intent(t)
	intent.Inbound.Listeners[0].Endpoint.Host = host
	intent.Inbound.Settings.Data = json.RawMessage(options)
	intent.AuthorizeBinding = func(_ context.Context, binding access.Binding) bool {
		return binding.ID == intent.Bindings[0].ID && allowed.Load()
	}
	compiled, err := (SOCKS5Compiler{}).Compile(ctx, intent)
	if err != nil {
		t.Fatal(err)
	}
	h := compiled.(*socks5Handle)
	t.Cleanup(func() {
		if err := h.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	h.udp.idle, h.udp.flowIdle = idle, flowIdle
	if err := h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	pair, err := proxy.Pair(intent.Credentials[0])
	if err != nil {
		t.Fatal(err)
	}
	return h, pair
}

func socks5UDPTestAssociate(t *testing.T, h *socks5Handle, pair *socks5.Credentials, request access.Endpoint) (net.Conn, access.Endpoint, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", h.listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	bind, err := socks5.ClientHandshake(c, socks5.UDPAssociate, request, pair)
	return c, bind, err
}

func requireSOCKS5UDPEOF(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("UDP control was not closed, bytes=%d: %v", n, err)
	}
}

func TestManagedSOCKS5UDPProtectedRelayLifecycle(t *testing.T) {
	underlays := testkit.NewUnderlay(t)
	lease, err := underlays.Factory.Begin(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := underlay.WithFactory(t.Context(), underlays.Factory)
	ctx = underlay.WithScope(ctx, underlay.Scope{Purpose: underlay.ServerTarget, Generation: lease.ID})
	var allowed atomic.Bool
	allowed.Store(true)
	h, pair := startSOCKS5UDPTest(t, ctx, "::1", `{"auth":true,"udp":true}`, &allowed, socks5UDPIdle, socks5UDPFlowIdle)
	mismatch, bind, err := socks5UDPTestAssociate(t, h, pair, access.Endpoint{Host: "2001:db8::3"})
	if err == nil || bind.Port != 0 {
		t.Fatal("association accepted an unrelated UDP source IP")
	}
	_ = mismatch.Close()
	client := listenSOCKS5UDPTest(t, "::1")
	control, bind, err := socks5UDPTestAssociate(t, h, pair, access.Endpoint{Host: "::"})
	if err != nil || bind.Host != "::1" || bind.Port == 0 {
		t.Fatalf("native IPv6 UDP relay bind failed: %v", err)
	}
	relay := netaddr.UDP(bind).(*net.UDPAddr)
	target := listenSOCKS5UDPTest(t, "::1")
	targetEndpoint, err := netaddr.From(target.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	write := func(payload []byte) {
		frame, err := socks5.EncodePacket(targetEndpoint, payload)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := client.WriteToUDP(frame, relay); err != nil || n != len(frame) {
			t.Fatalf("client datagram write failed: %v", err)
		}
	}
	var data [65535]byte
	// Simulated loss and response reordering occur at a real UDP target. The
	// unacknowledged datagram was received and must not stall later responses.
	var targetPeer *net.UDPAddr
	for _, marker := range []string{"lost", "first", "second"} {
		write([]byte(marker))
		_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, peer, err := target.ReadFromUDP(data[:])
		if err != nil || string(data[:n]) != marker {
			t.Fatalf("payload did not reach the native IPv6 target: %v", err)
		}
		if targetPeer != nil && targetPeer.String() != peer.String() {
			t.Fatal("same-target datagrams did not share a connected flow")
		}
		targetPeer = peer
	}
	for _, marker := range []string{"second", "first"} {
		if n, err := target.WriteToUDP([]byte(marker), targetPeer); err != nil || n != len(marker) {
			t.Fatalf("target response failed: %v", err)
		}
		_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, sender, err := client.ReadFromUDP(data[:])
		endpoint, payload, decodeErr := socks5.ParsePacket(data[:n])
		if err != nil || decodeErr != nil || sender.String() != relay.String() || endpoint != targetEndpoint || string(payload) != marker {
			t.Fatalf("response address or reordering mismatch: %v / %v", err, decodeErr)
		}
	}
	if count := underlays.Backend.Count(underlay.ServerTarget); count != 1 {
		t.Fatalf("expected one protected target socket, got %d", count)
	}
	allowed.Store(false)
	requireSOCKS5UDPEOF(t, control)
	var closers sync.WaitGroup
	for range 4 {
		closers.Go(func() {
			if err := h.Close(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	closers.Wait()
	if stats := h.Stats(); stats.Upload != 15 || stats.Download != 11 || stats.UDPSessions != 1 || stats.UDPActive != 0 {
		t.Fatalf("unexpected payload counts or active UDP resources: %+v", stats)
	}
	rebound, err := net.ListenUDP("udp6", relay)
	if err != nil {
		t.Fatalf("association relay socket not released: %v", err)
	}
	_ = rebound.Close()
	upstream, err := net.ListenUDP("udp6", targetPeer)
	if err != nil {
		t.Fatalf("protected target socket survived shutdown: %v", err)
	}
	_ = upstream.Close()
}

func TestManagedSOCKS5UDPPortExhaustionAndIdle(t *testing.T) {
	occupied := listenSOCKS5UDPTest(t, "127.0.0.1")
	addr := occupied.LocalAddr().(*net.UDPAddr)
	options, err := json.Marshal(map[string]any{"auth": true, "udp": true, "udp_relay": proxy.SOCKS5UDPRelay{
		PortMin: uint16(addr.Port), PortMax: uint16(addr.Port),
	}})
	if err != nil {
		t.Fatal(err)
	}
	var allowed atomic.Bool
	allowed.Store(true)
	ctx := underlay.WithFactory(t.Context(), underlay.New())
	h, pair := startSOCKS5UDPTest(t, ctx, "127.0.0.1", string(options), &allowed, 400*time.Millisecond, socks5UDPFlowIdle)
	request := access.Endpoint{Host: "0.0.0.0"}
	first, bind, err := socks5UDPTestAssociate(t, h, pair, request)
	if !errors.Is(err, socks5.ErrHandshake) || bind.Port != 0 {
		t.Fatalf("an occupied requested relay port returned success: %v", err)
	}
	_ = first.Close()
	_ = occupied.Close()
	open, bind, err := socks5UDPTestAssociate(t, h, pair, request)
	if err != nil || bind.Port != uint16(addr.Port) {
		t.Fatalf("freed requested port was not allocated: %v", err)
	}
	requireSOCKS5UDPEOF(t, open)
	reopened, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("idle association did not free its configured port: %v", err)
	}
	_ = reopened.Close()
}

func TestManagedSOCKS5UDPAssociationAndFlowBounds(t *testing.T) {
	r := newSOCKS5UDPRelay(proxy.SOCKS5UDPRelay{Listen: "127.0.0.1"})
	hosts := []netip.Addr{
		netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("127.0.0.3"), netip.MustParseAddr("127.0.0.4"),
	}
	for _, source := range hosts {
		for range socks5UDPSourceLimit {
			c, err := r.reserve(source)
			if err != nil {
				t.Fatal(err)
			}
			port := c.LocalAddr().(*net.UDPAddr).AddrPort().Port()
			t.Cleanup(func() { _ = c.Close(); r.release(source, port) })
		}
		if excess, err := r.reserve(source); err == nil {
			_ = excess.Close()
			t.Fatal("per-source UDP association limit was bypassed")
		}
	}
	if len(r.ports) != socks5UDPAssociationLimit {
		t.Fatalf("expected %d distinct UDP sockets, got %d", socks5UDPAssociationLimit, len(r.ports))
	}
	if excess, err := r.reserve(netip.MustParseAddr("127.0.0.5")); err == nil {
		_ = excess.Close()
		t.Fatal("total UDP association limit was bypassed")
	}

	h := &socks5Handle{udp: r}
	a := socks5UDPAssociation{handle: h, ctx: t.Context(), flows: make(map[access.Endpoint]*socks5UDPFlow),
		finished: make(chan access.Endpoint, socks5UDPFlowLimit)}
	for index := range socks5UDPFlowLimit {
		a.flows[access.Endpoint{Host: "127.0.0.1", Port: uint16(1000 + index)}] = &socks5UDPFlow{}
	}
	if got := a.flow(access.Endpoint{Host: "127.0.0.1", Port: 2000}, netip.AddrPort{}); got != nil {
		t.Error("per-association flow limit was bypassed")
	}
}

type testSOCKS5DatagramWriter struct {
	net.Conn
	err  error
	data []byte
}

func (w *testSOCKS5DatagramWriter) Write(payload []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.data = append(w.data[:0], payload...)
	return len(payload), nil
}

func TestManagedSOCKS5UDPDatagramWriteError(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	writer := &testSOCKS5DatagramWriter{Conn: raw, err: syscall.EMSGSIZE}
	a := socks5UDPAssociation{handle: &socks5Handle{udp: newSOCKS5UDPRelay(proxy.SOCKS5UDPRelay{Listen: "127.0.0.1"})}, ctx: t.Context()}
	flow := &socks5UDPFlow{conn: writer, target: access.Endpoint{Host: "127.0.0.1", Port: 1}}
	if a.write(flow, []byte("rejected by the UDP socket")) {
		t.Fatal("the datagram size error was counted as a successful write")
	}
	writer.err = nil
	payload := []byte("smaller datagram after the size error")
	if !a.write(flow, payload) || !bytes.Equal(writer.data, payload) {
		t.Fatal("a failed datagram write prevented the next datagram")
	}
}
