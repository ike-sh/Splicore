package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

var errProxySelfTarget = errors.New("proxy listener cannot be its own TCP peer")

func newManagedProxyHandle(ctx context.Context, in ports.RuntimeIntent, name string, limits managedProxyLimits) (*managedProxyHandle, error) {
	if !in.Inbound.Enabled || in.AuthorizeBinding == nil {
		return nil, identity.Err(identity.Unavailable, name+" runtime admission unavailable")
	}
	dialer, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &managedProxyHandle{
		name: name, limits: limits, ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint,
		dialer: ports.RoutedTargetDialer(ctx, dialer), connections: make(map[net.Conn]struct{}),
		authorize: in.AuthorizeBinding, authenticating: make(map[netip.Addr]int), done: make(chan struct{}),
	}
	for index, binding := range in.Bindings {
		pair := in.Credentials[index].Payload.(access.UsernamePasswordPayload)
		h.users = append(h.users, managedProxyUser{
			binding: binding, username: sha256.Sum256([]byte(pair.Username.Reveal())),
			password: sha256.Sum256([]byte(pair.Password.Reveal())), stats: &traffic.Counter{},
		})
	}
	return h, nil
}

type managedProxyUser struct {
	binding            access.Binding
	username, password [sha256.Size]byte
	stats              *traffic.Counter
}

type managedProxyLimits struct {
	connections, handshakes, perSource int
}

type managedProxyHandle struct {
	name      string
	limits    managedProxyLimits
	serve     func(net.Conn, func())
	ctx       context.Context
	cancel    context.CancelFunc
	dialer    ports.TargetDialer
	endpoint  access.Endpoint
	users     []managedProxyUser
	authorize func(context.Context, access.Binding) bool
	total     traffic.Counter

	mu             sync.Mutex
	listener       net.Listener
	connections    map[net.Conn]struct{}
	authenticating map[netip.Addr]int
	pending        int
	closed         bool
	admitted       bool
	running        atomic.Bool
	wg             sync.WaitGroup
	done           chan struct{}
}

func (h *managedProxyHandle) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, h.name+" runtime closed")
	}
	if h.listener != nil {
		return h.Health(ctx)
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, h.name+" TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, h.name+" listener start failed")
	}
	h.listener = listener
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept(listener)
	return nil
}

func (h *managedProxyHandle) Activate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.admitted = true
	}
}

func (h *managedProxyHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, h.name+" listener is not healthy")
	}
	return nil
}

func (h *managedProxyHandle) Stats() ports.Stats { return h.total.Snapshot() }

func (h *managedProxyHandle) BindingStats(id identity.ID) ports.Stats {
	for index := range h.users {
		user := &h.users[index]
		if user.binding.ID == id {
			return user.stats.Snapshot()
		}
	}
	return ports.Stats{}
}

func (h *managedProxyHandle) Close(ctx context.Context) error {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.running.Store(false)
		h.cancel()
		if h.listener != nil {
			_ = h.listener.Close()
		}
		for conn := range h.connections {
			_ = conn.Close()
		}
		go func() {
			h.wg.Wait()
			for index := range h.users {
				clear(h.users[index].username[:])
				clear(h.users[index].password[:])
			}
			close(h.done)
		}()
	}
	h.mu.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, h.name+" shutdown timed out")
	}
}

func (h *managedProxyHandle) accept(listener net.Listener) {
	defer h.wg.Done()
	defer h.running.Store(false)
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		source := conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap()
		h.mu.Lock()
		if h.closed || !h.admitted || len(h.connections) >= h.limits.connections ||
			h.pending >= h.limits.handshakes || h.authenticating[source] >= h.limits.perSource {
			h.mu.Unlock()
			_ = conn.Close()
			continue
		}
		h.connections[conn] = struct{}{}
		h.pending++
		h.authenticating[source]++
		h.wg.Add(1)
		h.mu.Unlock()
		go h.run(conn, source)
	}
}

func (h *managedProxyHandle) finishHandshake(source netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending--
	h.authenticating[source]--
	if h.authenticating[source] == 0 {
		delete(h.authenticating, source)
	}
}

func (h *managedProxyHandle) ownsDestination(target access.Endpoint) bool {
	if target.Port != h.endpoint.Port {
		return false
	}
	bound, _ := netip.ParseAddr(h.endpoint.Host)
	addr, err := netip.ParseAddr(target.Host)
	if err != nil {
		return false // The protected dial checks resolved numeric peers.
	}
	addr = addr.Unmap()
	if addr.IsUnspecified() || addr == bound.Unmap() {
		return true
	}
	if !bound.IsUnspecified() {
		return false
	}
	if addr.IsLoopback() {
		return true
	}
	interfaces, _ := net.InterfaceAddrs()
	for _, entry := range interfaces {
		if ip, ok := entry.(*net.IPNet); ok && ip.IP.Equal(addr.AsSlice()) {
			return true
		}
	}
	return false
}

func (h *managedProxyHandle) run(conn net.Conn, source netip.Addr) {
	defer h.wg.Done()
	defer func() {
		_ = conn.Close()
		h.mu.Lock()
		delete(h.connections, conn)
		h.mu.Unlock()
	}()
	finishHandshake := sync.OnceFunc(func() { h.finishHandshake(source) })
	defer finishHandshake()
	h.serve(conn, finishHandshake)
}

func (h *managedProxyHandle) authenticate(ctx context.Context, username, password string) *managedProxyUser {
	// Compare fixed-size digests against every configured user.
	nameHash, passHash := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
	match := -1
	for index := range h.users {
		user := &h.users[index]
		equal := subtle.ConstantTimeCompare(user.username[:], nameHash[:]) &
			subtle.ConstantTimeCompare(user.password[:], passHash[:])
		match = subtle.ConstantTimeSelect(equal, index, match)
	}
	if match >= 0 && h.authorize(ctx, h.users[match].binding) {
		return &h.users[match]
	}
	return nil
}

func (h *managedProxyHandle) dialTarget(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	if h.ownsDestination(target) {
		return nil, errProxySelfTarget
	}
	var blocked atomic.Bool
	ctx = underlay.WithTCPPeerCheck(ctx, func(peer netip.AddrPort) error {
		if h.ownsDestination(access.Endpoint{Host: peer.Addr().String(), Port: peer.Port()}) {
			blocked.Store(true)
			return errProxySelfTarget
		}
		return nil
	})
	remote, err := h.dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, portString(target.Port)))
	if err != nil {
		if blocked.Load() {
			return nil, errProxySelfTarget
		}
		return nil, err
	}
	if endpoint, err := netaddr.From(remote.RemoteAddr()); err == nil && h.ownsDestination(endpoint) {
		_ = remote.Close()
		return nil, errProxySelfTarget
	}
	return remote, nil
}
