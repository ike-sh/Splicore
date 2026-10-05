//go:build with_gvisor

package nativetun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// This peer is an in-memory protocol stack, not a socket to a third-party
// target. Both stacks, packet bytes and bridge goroutines are fixture-owned.
type stackPeer struct {
	stack  *stack.Stack
	link   *peerLink
	device *testDevice
	cancel context.CancelFunc
	worker sync.WaitGroup
}

func newStackPeer(t *testing.T, device *testDevice, dropReplies bool) *stackPeer {
	t.Helper()
	p := &stackPeer{device: device, stack: stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	}), link: &peerLink{channel.New(256, 1500, "")}}
	if err := p.stack.CreateNIC(1, p.link); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"198.18.0.2", "fd13::2"} {
		ip := netip.MustParseAddr(raw)
		protocol := header.IPv4ProtocolNumber
		if ip.Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		if err := p.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(ip.AsSlice()), PrefixLen: ip.BitLen()}}, stack.AddressProperties{}); err != nil {
			t.Fatal(err)
		}
	}
	p.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	device.write = func(data []byte) (int, error) {
		if dropReplies {
			return len(data), nil
		}
		protocol := header.IPv4ProtocolNumber
		if header.IPVersion(data) == 6 {
			protocol = header.IPv6ProtocolNumber
		}
		packet := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(data))})
		p.link.InjectInbound(protocol, packet)
		packet.DecRef()
		return len(data), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.worker.Add(1)
	go func() {
		defer p.worker.Done()
		for {
			packet := p.link.ReadContext(ctx)
			if packet == nil {
				return
			}
			var data []byte
			for _, part := range packet.AsSlices() {
				data = append(data, part...)
			}
			packet.DecRef()
			select {
			case device.read <- data:
			case <-ctx.Done():
				return
			case <-device.interrupted:
				return
			}
		}
	}()
	return p
}

func (p *stackPeer) close() { p.cancel(); p.worker.Wait(); p.stack.Destroy(); p.link.Close() }

// An asynchronous peer NIC must also snapshot borrowed headers before return.
type peerLink struct{ *channel.Endpoint }

func (l *peerLink) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, packet := range packets.AsSlice() {
		var data []byte
		for _, part := range packet.AsSlices() {
			data = append(data, part...)
		}
		owned := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		var list stack.PacketBufferList
		list.PushBack(owned)
		written, err := l.Endpoint.WritePackets(list)
		owned.DecRef()
		n += written
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestLinkRetainsImmutableEgressSnapshot(t *testing.T) {
	l := &packetLink{Endpoint: channel.New(2, 1500, ""), output: make(chan []byte, 2)}
	defer l.Close()
	original := bytes.Repeat([]byte{0x57}, 1500)
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(original))})
	var list stack.PacketBufferList
	list.PushBack(p)
	if n, err := l.WritePackets(list); n != 1 || err != nil {
		t.Fatal("enqueue", n, err)
	}
	// A caller may reuse every borrowed byte as soon as WritePackets returns.
	data, ok := p.Data().PullUp(len(original))
	if !ok {
		t.Fatal("payload missing")
	}
	clear(data)
	p.DecRef()
	if actual := l.readPacket(context.Background()); !bytes.Equal(actual, original) {
		t.Fatal("egress retained mutable caller storage")
	}
	l.Close()
	if n, err := l.WritePackets(stack.PacketBufferList{}); n != 0 || err == nil {
		t.Fatal("closed queue accepts writes", n, err)
	}
}

func echoDispatcher() testDispatcher {
	return testDispatcher{
		tcp: func(_ context.Context, c net.Conn, _, _ netip.AddrPort) { _, _ = io.Copy(c, c) },
		udp: func(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
			data := make([]byte, 65535)
			for {
				n, err := c.Read(data)
				if err != nil {
					return
				}
				if _, err = c.Write(data[:n]); err != nil {
					return
				}
			}
		},
	}
}

func TestNativeTCPUDPIPv4IPv6PacketOwnership(t *testing.T) {
	device := newTestDevice()
	peer := newStackPeer(t, device, false)
	defer peer.close()
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: echoDispatcher()})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !errors.Is(r.Start(), ErrStarted) {
		t.Fatal("double Start allowed")
	}
	for _, host := range []string{"198.19.0.1", "fd13:5678::1"} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+host, func(t *testing.T) {
				var workers sync.WaitGroup
				for i := range 8 {
					workers.Go(func() {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						ip := netip.MustParseAddr(host)
						protocol := header.IPv4ProtocolNumber
						if ip.Is6() {
							protocol = header.IPv6ProtocolNumber
						}
						address := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: uint16(8000 + i)}
						var c net.Conn
						var err error
						if network == "tcp" {
							c, err = gonet.DialContextTCP(ctx, peer.stack, address, protocol)
						} else {
							var queue waiter.Queue
							ep, stackErr := peer.stack.NewEndpoint(udp.ProtocolNumber, protocol, &queue)
							if stackErr == nil {
								stackErr = ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont))
							}
							if stackErr == nil {
								stackErr = ep.Connect(address)
							}
							if stackErr != nil {
								if ep != nil {
									ep.Close()
								}
								err = translate(stackErr)
							} else {
								c = gonet.NewUDPConn(&queue, ep)
							}
						}
						if err != nil {
							t.Error(err)
							return
						}
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(5 * time.Second))
						for round := range 8 {
							size := 1024
							if network == "udp" {
								size = 4096
							} // both IPv4/IPv6 fragment reassembly
							payload := bytes.Repeat([]byte{byte(i*8 + round)}, size)
							if _, err := c.Write(payload); err != nil {
								t.Error(err)
								return
							}
							actual := make([]byte, len(payload))
							if _, err := io.ReadFull(c, actual); err != nil {
								t.Error(err)
								return
							}
							if !bytes.Equal(payload, actual) {
								t.Error("packet backing bytes overwritten")
								return
							}
						}
					})
				}
				workers.Wait()
			})
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	b := r.backend.(*gvisorBackend)
	if t.Failed() {
		t.Logf("fragment diagnostics backend received=%d malformed=%d checksum=%d peer received=%d malformed=%d checksum=%d", b.stack.Stats().UDP.PacketsReceived.Value(), b.stack.Stats().UDP.MalformedPacketsReceived.Value(), b.stack.Stats().UDP.ChecksumErrors.Value(), peer.stack.Stats().UDP.PacketsReceived.Value(), peer.stack.Stats().UDP.MalformedPacketsReceived.Value(), peer.stack.Stats().UDP.ChecksumErrors.Value())
	}
	if len(b.active) != 0 || device.closes.Load() != 0 {
		t.Fatal("flow/device ownership residue")
	}
}

func TestCancelDuringTCPHandshake(t *testing.T) {
	device := newTestDevice()
	peer := newStackPeer(t, device, true)
	defer peer.close()
	registered := make(chan struct{})
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{
		tcp: func(_ context.Context, conn net.Conn, _, _ netip.AddrPort) {
			c := conn.(*lazyTCP)
			go func() { <-c.ready; close(registered) }()
			_, _ = c.Read(make([]byte, 1))
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		c, _ := gonet.DialContextTCP(ctx, peer.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 19, 0, 1}), Port: 443}, header.IPv4ProtocolNumber)
		if c != nil {
			c.Close()
		}
	}()
	select {
	case <-registered:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake did not reach registration barrier")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on incomplete handshake")
	}
	cancel()
	<-dialDone
}

func TestTCPDispatcherCloseDeliversFinalBytes(t *testing.T) {
	device := newTestDevice()
	peer := newStackPeer(t, device, false)
	defer peer.close()
	payload := bytes.Repeat([]byte("final TCP reply"), 4096)
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{
		tcp: func(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
			if _, err := c.Write(payload); err != nil {
				t.Error(err)
			}
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, peer.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 19, 0, 1}), Port: 443}, header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	actual, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("final reply truncated/reset: bytes=%d expected=%d err=%v", len(actual), len(payload), err)
	}
}

type failedReadDevice struct{ *testDevice }

func (d *failedReadDevice) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestPacketWorkerFailureRemainsVisibleAfterJoin(t *testing.T) {
	device := &failedReadDevice{newTestDevice()}
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Start() // failure can arrive before or after Start's publication
	if err := r.Wait(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("packet error lost", err)
	}
	if r.State() != Failed || device.closes.Load() != 0 {
		t.Fatal("failed runtime state/ownership")
	}
	if err := r.Close(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("Close lost terminal failure", err)
	}
}

func TestRejectedTCPDoesNotAcceptHandshake(t *testing.T) {
	device := newTestDevice()
	peer := newStackPeer(t, device, false)
	defer peer.close()
	r, _ := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := gonet.DialContextTCP(ctx, peer.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 19, 0, 1}), Port: 443}, header.IPv4ProtocolNumber)
	if c != nil {
		c.Close()
		t.Fatal("rejected flow completed a local handshake")
	}
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected immediate RST rejection", err)
	}
}

func TestNativeLifecycle25xGoroutineOwnership(t *testing.T) {
	cycle := func() {
		device := newTestDevice()
		r, _ := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if len(r.backend.(*gvisorBackend).active) != 0 {
			t.Fatal("flow residue")
		}
	}
	cycle()
	runtime.GC()
	start := runtime.NumGoroutine()
	peak := start
	for range 25 {
		cycle()
		peak = max(peak, runtime.NumGoroutine())
	}
	runtime.GC()
	end := runtime.NumGoroutine()
	t.Logf("native runtime cycles=25 goroutines start=%d peak=%d end=%d eventfd=NOT PRESENT", start, peak, end)
	if end != start {
		t.Fatalf("goroutine baseline changed: %d -> %d", start, end)
	}
}
