package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
)

const (
	socks5UDPAssociationLimit = 64
	socks5UDPSourceLimit      = 16
	socks5UDPFlowLimit        = 32
	socks5UDPIdle             = time.Minute
	socks5UDPFlowIdle         = 30 * time.Second
	socks5UDPAuthInterval     = time.Second
	socks5UDPWriteTimeout     = 2 * time.Second
	socks5UDPDialTimeout      = 5 * time.Second
	socks5UDPBufferSize       = 65535
)

var errSOCKS5UDPRelay = errors.New("SOCKS5 UDP relay unavailable or disallowed")

type socks5UDPRelay struct {
	settings proxy.SOCKS5UDPRelay
	ip       netip.Addr
	network  string
	idle     time.Duration
	flowIdle time.Duration

	mu      sync.RWMutex
	sources map[netip.Addr]int
	ports   map[uint16]struct{}
	next    uint16
}

func newSOCKS5UDPRelay(settings proxy.SOCKS5UDPRelay) *socks5UDPRelay {
	ip := netip.MustParseAddr(settings.Listen)
	network := "udp6"
	if ip.Is4() {
		network = "udp4"
	}
	return &socks5UDPRelay{settings: settings, ip: ip, network: network,
		idle: socks5UDPIdle, flowIdle: socks5UDPFlowIdle, sources: make(map[netip.Addr]int),
		ports: make(map[uint16]struct{}), next: settings.PortMin}
}

func (r *socks5UDPRelay) reserve(source netip.Addr) (*net.UDPConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ports) >= socks5UDPAssociationLimit || r.sources[source] >= socks5UDPSourceLimit {
		return nil, errSOCKS5UDPRelay
	}
	for range int(r.settings.PortMax) - int(r.settings.PortMin) + 1 {
		port := r.next
		if port == r.settings.PortMax {
			r.next = r.settings.PortMin
		} else {
			r.next++
		}
		if _, owned := r.ports[port]; owned {
			continue
		}
		socket, err := net.ListenUDP(r.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(r.ip, port)))
		if err != nil {
			if port != 0 {
				continue
			}
			return nil, err
		}
		bound := socket.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		if _, owned := r.ports[bound]; owned {
			_ = socket.Close()
			continue
		}
		r.ports[bound] = struct{}{}
		r.sources[source]++
		return socket, nil
	}
	return nil, errSOCKS5UDPRelay
}

func (r *socks5UDPRelay) release(source netip.Addr, port uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ports, port)
	r.sources[source]--
	if r.sources[source] == 0 {
		delete(r.sources, source)
	}
}

func (r *socks5UDPRelay) checkTarget(target access.Endpoint) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.checkTargetLocked(target)
}

func (r *socks5UDPRelay) checkTargetLocked(target access.Endpoint) error {
	ip, err := netip.ParseAddr(target.Host)
	if err != nil {
		return nil // The connected socket's numeric peer is checked before any write.
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return errSOCKS5UDPRelay
	}
	if _, listening := r.ports[target.Port]; !listening || ip.Is4() != r.ip.Is4() {
		return nil
	}
	if ip == r.ip || r.ip.IsUnspecified() && isLocalUDPAddress(ip) {
		return errSOCKS5UDPRelay
	}
	return nil
}

func isLocalUDPAddress(ip netip.Addr) bool {
	if ip.IsLoopback() {
		return true
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok && network.IP.Equal(ip.AsSlice()) {
			return true
		}
	}
	return false
}

func (h *socks5Handle) associateUDP(control *net.TCPConn, requested access.Endpoint, user *managedProxyUser, finishHandshake func()) {
	peer := control.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
	wantIP, err := netip.ParseAddr(requested.Host)
	emptyBind := &net.TCPAddr{IP: net.IPv4zero}
	if err != nil || (!wantIP.IsUnspecified() && wantIP.Unmap() != peer.WithZone("")) || peer.Is4() != h.udp.ip.Is4() {
		_ = socks5.Respond(control, socks5.NotAllowed, emptyBind)
		return
	}
	if !h.udpAuthorized(h.ctx, user) {
		_ = socks5.Respond(control, socks5.NotAllowed, emptyBind)
		return
	}
	socket, err := h.udp.reserve(peer)
	if err != nil {
		_ = socks5.Respond(control, socks5.Failure, emptyBind)
		return
	}
	port := socket.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	defer h.udp.release(peer, port)
	defer socket.Close()

	if h.ctx.Err() != nil {
		return
	}
	advertised := netaddr.UDP(access.Endpoint{Host: h.udp.settings.Advertise, Port: port})
	if socks5.Respond(control, socks5.Succeeded, advertised) != nil || control.SetDeadline(time.Time{}) != nil {
		return
	}
	counters := []*traffic.Counter{&h.total, user.stats}
	closeStats := traffic.Open(false, counters...)
	defer closeStats()
	finishHandshake()
	ctx, cancel := context.WithCancel(h.ctx)
	association := socks5UDPAssociation{handle: h, user: user, socket: socket, ctx: ctx, counters: counters,
		started: time.Now(), flows: make(map[access.Endpoint]*socks5UDPFlow),
		finished: make(chan access.Endpoint, socks5UDPFlowLimit)}
	association.stop = sync.OnceFunc(func() { cancel(); _ = socket.Close() })
	association.workers.Go(func() {
		// UDP data has no framing on the control stream. EOF, an error or
		// unexpected TCP data all terminate this association.
		var extra [1]byte
		_, _ = control.Read(extra[:])
		association.stop()
	})
	defer func() {
		association.stop()
		_ = control.Close()
		for _, flow := range association.flows {
			flow.close()
		}
		association.workers.Wait()
	}()
	association.receive(peer, requested.Port)
}

func (h *socks5Handle) udpAuthorized(ctx context.Context, user *managedProxyUser) bool {
	ctx, cancel := context.WithTimeout(ctx, socks5UDPAuthInterval)
	defer cancel()
	return ctx.Err() == nil && h.authorize(ctx, user.binding) && ctx.Err() == nil
}

type socks5UDPAssociation struct {
	handle   *socks5Handle
	user     *managedProxyUser
	socket   *net.UDPConn
	ctx      context.Context
	stop     func()
	counters []*traffic.Counter
	started  time.Time
	activity atomic.Int64

	// Only the request loop owns the flow map and registers new workers.
	workers  sync.WaitGroup
	flows    map[access.Endpoint]*socks5UDPFlow
	finished chan access.Endpoint
}

type socks5UDPFlow struct {
	conn   net.Conn
	target access.Endpoint
	close  func()
}

func (a *socks5UDPAssociation) noteActivity() {
	elapsed := int64(time.Since(a.started))
	for before := a.activity.Load(); before < elapsed && !a.activity.CompareAndSwap(before, elapsed); before = a.activity.Load() {
	}
}

func (a *socks5UDPAssociation) receive(peer netip.Addr, port uint16) {
	buffer := make([]byte, socks5UDPBufferSize)
	nextAuth := time.Now().Add(socks5UDPAuthInterval)
	for a.ctx.Err() == nil {
		now := time.Now()
		idleAt := a.started.Add(time.Duration(a.activity.Load()) + a.handle.udp.idle)
		if !now.Before(idleAt) {
			return
		}
		if !now.Before(nextAuth) {
			if !a.handle.udpAuthorized(a.ctx, a.user) {
				return
			}
			nextAuth = now.Add(socks5UDPAuthInterval)
		}
		deadline := idleAt
		if nextAuth.Before(deadline) {
			deadline = nextAuth
		}
		if a.socket.SetReadDeadline(deadline) != nil {
			return
		}
		n, source, err := a.socket.ReadFromUDPAddrPort(buffer)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return
		}
		if source.Addr().Unmap() != peer || (port != 0 && source.Port() != port) {
			continue
		}
		target, payload, err := socks5.ParsePacket(buffer[:n])
		if err != nil || a.handle.udp.checkTarget(target) != nil {
			continue
		}
		if !a.handle.udpAuthorized(a.ctx, a.user) {
			return
		}
		if port == 0 {
			port = source.Port()
		}
		flow := a.flow(target, source)
		if flow == nil {
			continue
		}
		if a.write(flow, payload) {
			traffic.CountUpload(len(payload), a.counters...)
			a.noteActivity()
		}
	}
}

func (a *socks5UDPAssociation) flow(target access.Endpoint, source netip.AddrPort) *socks5UDPFlow {
	for pending := len(a.finished); pending > 0; pending-- {
		delete(a.flows, <-a.finished)
	}
	if flow := a.flows[target]; flow != nil {
		return flow
	}
	if len(a.flows) >= socks5UDPFlowLimit {
		return nil
	}
	ctx, cancel := context.WithTimeout(a.ctx, socks5UDPDialTimeout)
	defer cancel()
	ctx = ports.WithDirectServerTarget(ctx, "udp", a.handle.udp.checkTarget)
	conn, err := a.handle.dialer.DialContext(ctx, "udp", net.JoinHostPort(target.Host, portString(target.Port)))
	if err != nil {
		return nil
	}
	remote, err := netaddr.From(conn.RemoteAddr())
	_, ipErr := netip.ParseAddr(remote.Host)
	if err != nil || ipErr != nil || remote.Validate() != nil || a.handle.udp.checkTarget(remote) != nil || ctx.Err() != nil {
		_ = conn.Close()
		return nil
	}
	flow := &socks5UDPFlow{conn: conn, target: remote, close: sync.OnceFunc(func() { _ = conn.Close() })}
	a.flows[target] = flow
	a.workers.Go(func() {
		defer func() {
			flow.close()
			a.finished <- target
		}()
		a.responses(flow, source)
	})
	return flow
}

func (a *socks5UDPAssociation) write(flow *socks5UDPFlow, payload []byte) bool {
	relay := a.handle.udp
	if a.ctx.Err() != nil || flow.conn.SetWriteDeadline(time.Now().Add(socks5UDPWriteTimeout)) != nil ||
		flow.conn.SetReadDeadline(time.Now().Add(relay.flowIdle)) != nil {
		return false
	}
	// Hold the relay reservation through the write so that a newly opened
	// local association cannot become this connected flow's target.
	relay.mu.RLock()
	defer relay.mu.RUnlock()
	if relay.checkTargetLocked(flow.target) != nil {
		return false
	}
	n, err := flow.conn.Write(payload)
	return err == nil && n == len(payload)
}

func (a *socks5UDPAssociation) responses(flow *socks5UDPFlow, client netip.AddrPort) {
	buffer := make([]byte, socks5UDPBufferSize)
	for a.ctx.Err() == nil {
		if flow.conn.SetReadDeadline(time.Now().Add(a.handle.udp.flowIdle)) != nil {
			return
		}
		n, err := flow.conn.Read(buffer)
		if err != nil {
			return
		}
		frame, err := socks5.EncodePacket(flow.target, buffer[:n])
		if err != nil {
			continue
		}
		if !a.handle.udpAuthorized(a.ctx, a.user) {
			a.stop()
			return
		}
		sent, err := a.socket.WriteToUDPAddrPort(frame, client)
		if err == nil && sent == len(frame) {
			traffic.CountDownload(n, a.counters...)
			a.noteActivity()
		}
	}
}
