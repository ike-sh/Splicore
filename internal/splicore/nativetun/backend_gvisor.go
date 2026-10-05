//go:build with_gvisor

package nativetun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const Included = true
const flowLimit = 4096

type flowKey struct {
	protocol tcpip.TransportProtocolNumber
	id       stack.TransportEndpointID
}

type gvisorBackend struct {
	runtime  *Runtime
	stack    *stack.Stack
	link     *packetLink
	workers  sync.WaitGroup
	flows    sync.WaitGroup
	mu       sync.Mutex // callback admission/publication only
	stopping bool
	active   map[flowKey]net.Conn // nil is a reserved, not-yet-running callback
}

func startBackend(r *Runtime) (backend, error) {
	b := &gvisorBackend{runtime: r, active: make(map[flowKey]net.Conn)}
	b.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	b.link = &packetLink{Endpoint: channel.New(256, r.options.MTU, ""), backend: b, output: make(chan []byte, 256)}
	f := tcp.NewForwarder(b.stack, 0, flowLimit, b.tcpFlow)
	// Handler publication is initialization-only, before NIC attachment/ingress.
	b.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, p *stack.PacketBuffer) bool {
		key := flowKey{tcp.ProtocolNumber, id}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.stopping || r.ctx.Err() != nil {
			return true
		}
		if _, exists := b.active[key]; exists {
			return true
		}
		if len(b.active) >= flowLimit {
			return true
		}
		b.active[key] = nil
		b.flows.Add(1) // reserve before upstream launches its callback goroutine
		if !f.HandlePacket(id, p) {
			delete(b.active, key)
			b.flows.Done()
			return false
		}
		return true
	})
	u := udp.NewForwarder(b.stack, b.udpFlow)
	b.stack.SetTransportProtocolHandler(udp.ProtocolNumber, u.HandlePacket)
	b.stack.SetTransportProtocolHandler(icmp.ProtocolNumber4, b.icmpHandler(header.IPv4ProtocolNumber))
	b.stack.SetTransportProtocolHandler(icmp.ProtocolNumber6, b.icmpHandler(header.IPv6ProtocolNumber))
	if err := b.stack.CreateNIC(1, b.link); err != nil {
		b.stack.Destroy()
		return nil, translate(err)
	}
	if err := b.stack.SetPromiscuousMode(1, true); err != nil {
		b.stack.Destroy()
		return nil, translate(err)
	}
	if err := b.stack.SetSpoofing(1, true); err != nil {
		b.stack.Destroy()
		return nil, translate(err)
	}
	for _, address := range r.options.Addresses {
		protocol := header.IPv4ProtocolNumber
		if address.Is6() {
			protocol = header.IPv6ProtocolNumber
		}
		if err := b.stack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: protocol, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(address.AsSlice()), PrefixLen: address.BitLen()}}, stack.AddressProperties{}); err != nil {
			b.stack.Destroy()
			return nil, translate(err)
		}
	}
	b.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	b.workers.Add(2)
	go b.receive()
	go b.send()
	return b, nil
}

func (b *gvisorBackend) finished(key flowKey) {
	b.mu.Lock()
	delete(b.active, key)
	b.mu.Unlock()
	b.flows.Done()
}

func (b *gvisorBackend) publish(key flowKey, c net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopping || b.runtime.ctx.Err() != nil {
		return false
	}
	b.active[key] = c
	return true
}

func addresses(id stack.TransportEndpointID) (netip.AddrPort, netip.AddrPort) {
	source, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	destination, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	return netip.AddrPortFrom(source.Unmap(), id.RemotePort), netip.AddrPortFrom(destination.Unmap(), id.LocalPort)
}

func (b *gvisorBackend) tcpFlow(request *tcp.ForwarderRequest) {
	id := request.ID()
	key := flowKey{tcp.ProtocolNumber, id}
	defer b.finished(key)
	c := newLazyTCP(b, request, id)
	defer c.Close()
	if !b.publish(key, c) {
		return
	}
	source, destination := addresses(id)
	b.runtime.options.Dispatcher.TCP(b.runtime.ctx, c, source, destination)
}

func (b *gvisorBackend) udpFlow(request *udp.ForwarderRequest) bool {
	id := request.ID()
	key := flowKey{udp.ProtocolNumber, id}
	b.mu.Lock()
	if b.stopping || b.runtime.ctx.Err() != nil || len(b.active) >= flowLimit {
		b.mu.Unlock()
		return false // official forwarder releases its cloned request packet
	}
	if _, exists := b.active[key]; exists {
		b.mu.Unlock()
		return false
	}
	// Endpoint creation is short and synchronous. Stop cannot pass publication.
	var queue waiter.Queue
	ep, err := request.CreateEndpoint(&queue)
	if err != nil {
		b.mu.Unlock()
		return true
	}
	// This packet link has no segmentation offload. Permit stack fragmentation
	// with non-atomic IPv4 identifiers, rather than DF + ID zero fragments.
	if err := ep.SetSockOptInt(tcpip.MTUDiscoverOption, int(tcpip.PMTUDiscoveryDont)); err != nil {
		ep.Close()
		b.mu.Unlock()
		return true
	}
	c := &flowConn{Conn: gonet.NewUDPConn(&queue, ep)}
	b.active[key] = c
	b.flows.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.finished(key)
		defer c.Close()
		source, destination := addresses(id)
		b.runtime.options.Dispatcher.UDP(b.runtime.ctx, c, source, destination)
	}()
	return true
}

func (b *gvisorBackend) receive() {
	defer b.workers.Done()
	data := make([]byte, 65535)
	for b.runtime.ctx.Err() == nil {
		n, err := b.runtime.device.Read(data)
		if err != nil {
			b.fail(err)
			return
		}
		if n == 0 {
			continue
		}
		var protocol tcpip.NetworkProtocolNumber
		switch header.IPVersion(data[:n]) {
		case 4:
			protocol = header.IPv4ProtocolNumber
		case 6:
			protocol = header.IPv6ProtocolNumber
		default:
			continue
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), data[:n]...)), IsForwardedPacket: true})
		b.link.InjectInbound(protocol, p)
		p.DecRef()
	}
}

func (b *gvisorBackend) send() {
	defer b.workers.Done()
	for b.runtime.ctx.Err() == nil {
		data := b.link.readPacket(b.runtime.ctx)
		if data == nil {
			return
		}
		_, err := b.runtime.writer.WritePacket(data)
		if err != nil {
			b.fail(err)
			return
		}
	}
}

func (b *gvisorBackend) fail(err error) {
	if b.runtime.ctx.Err() != nil {
		return
	}
	b.runtime.mu.Lock()
	b.runtime.err = errors.Join(b.runtime.err, cleanError(err))
	b.runtime.mu.Unlock()
	b.runtime.cancel() // owned lifecycle worker performs shutdown, outside packet worker
}

func (b *gvisorBackend) close() {
	b.mu.Lock()
	b.stopping = true
	connections := make([]net.Conn, 0, len(b.active))
	for _, c := range b.active {
		if c != nil {
			connections = append(connections, c)
		}
	}
	b.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
	b.workers.Wait()
	b.flows.Wait() // reservation covers callbacks that have not run yet
	b.stack.Destroy()
	b.link.Close() // also safe if a partially created NIC did not own the link
}

// packetLink observes the official stack's first output after TCP endpoint
// registration. This public link callback is the handshake-start barrier:
// cancellation can Abort the exact registered endpoint without polling,
// racing endpoint creation or changing handshake timers/wire behavior.
type packetLink struct {
	*channel.Endpoint
	backend *gvisorBackend
	output  chan []byte
	queueMu sync.RWMutex // enqueue vs close only; never device I/O
	closed  bool
}

func (l *packetLink) WritePackets(packets stack.PacketBufferList) (int, tcpip.Error) {
	l.queueMu.RLock()
	defer l.queueMu.RUnlock()
	if l.closed {
		return 0, &tcpip.ErrClosedForSend{}
	}
	n := 0
	for _, p := range packets.AsSlice() {
		if p.TransportProtocolNumber == tcp.ProtocolNumber && len(p.TransportHeader().Slice()) >= header.TCPMinimumSize {
			t := header.TCP(p.TransportHeader().Slice())
			id := stack.TransportEndpointID{LocalAddress: p.EgressRoute.LocalAddress, RemoteAddress: p.EgressRoute.RemoteAddress, LocalPort: t.SourcePort(), RemotePort: t.DestinationPort()}
			l.backend.mu.Lock()
			c, _ := l.backend.active[flowKey{tcp.ProtocolNumber, id}].(*lazyTCP)
			l.backend.mu.Unlock()
			if c != nil {
				c.signalReady()
			}
		}
		// Snapshot before returning to the stack. PacketBuffer.Clone retains
		// references but does not make mutable fragment/header views immutable.
		var data []byte
		for _, part := range p.AsSlices() {
			data = append(data, part...)
		}
		select {
		case l.output <- data:
			n++
		default:
			return n, &tcpip.ErrNoBufferSpace{}
		}
	}
	return n, nil
}

func (l *packetLink) readPacket(ctx context.Context) []byte {
	select {
	case data := <-l.output:
		return data
	case <-ctx.Done():
		return nil
	}
}
func (l *packetLink) Close() {
	l.queueMu.Lock()
	l.closed = true
	for len(l.output) > 0 {
		<-l.output
	}
	l.queueMu.Unlock()
	l.Endpoint.Close()
}

func translate(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	switch err.(type) {
	case *tcpip.ErrClosedForReceive, *tcpip.ErrClosedForSend, *tcpip.ErrConnectionAborted:
		return net.ErrClosed
	case *tcpip.ErrTimeout:
		return context.DeadlineExceeded
	case *tcpip.ErrNetworkUnreachable, *tcpip.ErrHostUnreachable:
		return errors.New("native TUN network unreachable")
	case *tcpip.ErrNoBufferSpace:
		return errors.New("native TUN resource exhausted")
	default:
		return errors.New("native TUN stack operation failed")
	}
}

// Upper layers never depend on gonet/tcpip concrete error types.
func cleanError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return net.ErrClosed
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return context.DeadlineExceeded
	}
	// EOF and standard syscall errors retain their standard Go identity.
	var op *net.OpError
	if errors.As(err, &op) {
		return errors.New("native TUN flow operation failed")
	}
	return err
}

type flowConn struct{ net.Conn }

func (c *flowConn) Read(p []byte) (int, error)  { n, e := c.Conn.Read(p); return n, cleanError(e) }
func (c *flowConn) Write(p []byte) (int, error) { n, e := c.Conn.Write(p); return n, cleanError(e) }
