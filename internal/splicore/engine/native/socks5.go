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
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

const (
	socks5HandshakeTimeout     = 10 * time.Second
	socks5ConnectTimeout       = 10 * time.Second
	socks5HandshakeLimit       = 64
	socks5SourceHandshakeLimit = 8
	socks5ConnectionLimit      = 512
)

var errSOCKS5SelfTarget = errors.New("SOCKS5 listener cannot be its own TCP peer")

type SOCKS5Compiler struct{}

func (SOCKS5Compiler) ProtocolID() string { return "socks5" }

func (SOCKS5Compiler) Supports(in ports.RuntimeIntent) error {
	_, err := (proxy.SOCKS5Inbound{}).BuildRuntime(context.Background(), in)
	return err
}

func (c SOCKS5Compiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	if !in.Inbound.Enabled || in.AuthorizeBinding == nil {
		return nil, identity.Err(identity.Unavailable, "SOCKS5 runtime admission unavailable")
	}
	dialer, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &socks5Handle{
		ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint,
		dialer: ports.RoutedTargetDialer(ctx, dialer), connections: make(map[net.Conn]struct{}),
		authorize: in.AuthorizeBinding, authenticating: make(map[netip.Addr]int), done: make(chan struct{}),
	}
	for index, binding := range in.Bindings {
		pair := in.Credentials[index].Payload.(access.UsernamePasswordPayload)
		h.users = append(h.users, socks5User{
			binding: binding, username: sha256.Sum256([]byte(pair.Username.Reveal())),
			password: sha256.Sum256([]byte(pair.Password.Reveal())), stats: &traffic.Counter{},
		})
	}
	return h, nil
}

type socks5User struct {
	binding            access.Binding
	username, password [sha256.Size]byte
	stats              *traffic.Counter
}

type socks5Handle struct {
	ctx       context.Context
	cancel    context.CancelFunc
	dialer    ports.TargetDialer
	endpoint  access.Endpoint
	users     []socks5User
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

func (h *socks5Handle) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "SOCKS5 runtime closed")
	}
	if h.listener != nil {
		return h.Health(ctx)
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "SOCKS5 TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "SOCKS5 listener start failed")
	}
	h.listener = listener
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept(listener)
	return nil
}

func (h *socks5Handle) Activate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.admitted = true
	}
}

func (h *socks5Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "SOCKS5 listener is not healthy")
	}
	return nil
}

func (h *socks5Handle) Stats() ports.Stats { return h.total.Snapshot() }

func (h *socks5Handle) BindingStats(id identity.ID) ports.Stats {
	for index := range h.users {
		user := &h.users[index]
		if user.binding.ID == id {
			return user.stats.Snapshot()
		}
	}
	return ports.Stats{}
}

func (h *socks5Handle) Close(ctx context.Context) error {
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
		return identity.Err(identity.Unavailable, "SOCKS5 shutdown timed out")
	}
}

func (h *socks5Handle) accept(listener net.Listener) {
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
		if h.closed || !h.admitted || len(h.connections) >= socks5ConnectionLimit ||
			h.pending >= socks5HandshakeLimit || h.authenticating[source] >= socks5SourceHandshakeLimit {
			h.mu.Unlock()
			_ = conn.Close()
			continue
		}
		h.connections[conn] = struct{}{}
		h.pending++
		h.authenticating[source]++
		h.wg.Add(1)
		h.mu.Unlock()
		go h.serve(conn, source)
	}
}

func (h *socks5Handle) finishHandshake(source netip.Addr) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pending--
	h.authenticating[source]--
	if h.authenticating[source] == 0 {
		delete(h.authenticating, source)
	}
}

func (h *socks5Handle) ownsDestination(target access.Endpoint) bool {
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

func (h *socks5Handle) serve(conn net.Conn, source netip.Addr) {
	defer h.wg.Done()
	defer func() {
		_ = conn.Close()
		h.mu.Lock()
		delete(h.connections, conn)
		h.mu.Unlock()
	}()
	pending := true
	defer func() {
		if pending {
			h.finishHandshake(source)
		}
	}()

	authCtx, finishAuth := context.WithTimeout(h.ctx, socks5HandshakeTimeout)
	defer finishAuth()
	deadline, _ := authCtx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return
	}
	match := -1
	err := socks5.AcceptRequiredAuth(conn, conn, func(username, password string) bool {
		// Compare fixed-size digests against every configured user, including
		// when the username is unknown.
		nameHash, passHash := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
		for index := range h.users {
			user := &h.users[index]
			equal := subtle.ConstantTimeCompare(user.username[:], nameHash[:]) &
				subtle.ConstantTimeCompare(user.password[:], passHash[:])
			match = subtle.ConstantTimeSelect(equal, index, match)
		}
		return match >= 0 && h.authorize(authCtx, h.users[match].binding)
	})
	finishAuth()
	if err != nil || h.ctx.Err() != nil {
		return
	}

	emptyBind := &net.TCPAddr{IP: net.IPv4zero}
	command, target, err := socks5.ReadCommand(conn)
	if err != nil {
		if errors.Is(err, address.ErrAddress) {
			_ = socks5.Respond(conn, socks5.UnsupportedAddress, emptyBind)
		}
		return
	}
	if command != socks5.Connect {
		_ = socks5.Respond(conn, socks5.UnsupportedCommand, emptyBind)
		return
	}
	if target.Validate() != nil {
		_ = socks5.Respond(conn, socks5.UnsupportedAddress, emptyBind)
		return
	}
	if h.ownsDestination(target) {
		_ = socks5.Respond(conn, socks5.NotAllowed, emptyBind)
		return
	}
	ctx, cancel := context.WithTimeout(h.ctx, socks5ConnectTimeout)
	ctx = underlay.WithTCPPeerCheck(ctx, func(peer netip.AddrPort) error {
		if h.ownsDestination(access.Endpoint{Host: peer.Addr().String(), Port: peer.Port()}) {
			return errSOCKS5SelfTarget
		}
		return nil
	})
	remote, err := h.dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, portString(target.Port)))
	cancel()
	_ = conn.SetWriteDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err != nil {
		reply := socks5.ErrorReply(err)
		if errors.Is(err, errSOCKS5SelfTarget) {
			reply = socks5.NotAllowed
		}
		_ = socks5.Respond(conn, reply, emptyBind)
		return
	}
	defer remote.Close()
	if endpoint, err := netaddr.From(remote.RemoteAddr()); err == nil && h.ownsDestination(endpoint) {
		_ = socks5.Respond(conn, socks5.NotAllowed, emptyBind)
		return
	}
	bind, ok := remote.LocalAddr().(*net.TCPAddr)
	if !ok {
		bind = emptyBind
	}
	if socks5.Respond(conn, socks5.Succeeded, bind) != nil || conn.SetDeadline(time.Time{}) != nil {
		return
	}
	h.finishHandshake(source)
	pending = false
	relay.Join(h.ctx, traffic.Conn(conn, &h.total, h.users[match].stats), remote)
}
