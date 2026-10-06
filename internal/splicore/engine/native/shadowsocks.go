package native

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks/wire"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type shadowsocksReplayState struct {
	salts      *wire.SaltCache
	packets    *wire.UDPReplay
	references int
	retired    time.Time
}

// Compiler owns a bounded replay registry for one Application Service lifetime.
// Restart/disable/rollback of an inbound cannot discard its recent replay state.
type ShadowsocksCompiler struct {
	mu     sync.Mutex
	states map[identity.ID]*shadowsocksReplayState
}

func NewShadowsocksCompiler() *ShadowsocksCompiler {
	return &ShadowsocksCompiler{states: map[identity.ID]*shadowsocksReplayState{}}
}
func (*ShadowsocksCompiler) ProtocolID() string { return "shadowsocks" }
func (*ShadowsocksCompiler) Supports(in ports.RuntimeIntent) error {
	s, e := module.Decode(in.Inbound.Settings.Data)
	if e != nil {
		return e
	}
	m, _ := module.Lookup(s.Method)
	_, e = (module.Module{Edition: m.Edition}).BuildRuntime(context.Background(), in)
	return e
}
func (c *ShadowsocksCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if e := c.Supports(in); e != nil {
		return nil, e
	}
	if _, e := underlay.FromContext(ctx); e != nil {
		return nil, e
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	m, _ := module.Lookup(s.Method)
	c.mu.Lock()
	if c.states == nil {
		c.states = map[identity.ID]*shadowsocksReplayState{}
	}
	for id, old := range c.states {
		if old.references == 0 && time.Since(old.retired) > 5*time.Minute {
			delete(c.states, id)
		}
	}
	state := c.states[in.Inbound.ID]
	if state == nil {
		if len(c.states) >= 128 {
			c.mu.Unlock()
			return nil, identity.Err(identity.Unavailable, "shadowsocks replay registry capacity reached")
		}
		life := 5 * time.Minute
		if m.Edition == "2022" {
			life = 60 * time.Second
		}
		state = &shadowsocksReplayState{salts: wire.NewSaltCache(8192, life), packets: wire.NewUDPReplay(512)}
		c.states[in.Inbound.ID] = state
	}
	state.references++
	c.mu.Unlock()
	retire := func() { c.mu.Lock(); state.references--; state.retired = time.Now(); c.mu.Unlock() }
	prepared := false
	defer func() {
		if !prepared {
			retire()
		}
	}()
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &shadowsocksHandle{ctx: runtimeCtx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, inbound: in.Inbound.ID, udp: s.UDP, total: &meter{}, users: map[identity.ID]*meter{}, connections: map[net.Conn]bool{}, sessions: map[shadowsocksAssociationID]*shadowsocksServerPacket{}, replay: state, done: make(chan struct{})}
	for n, b := range in.Bindings {
		keys, e := wire.Keys(s.Method, module.Material(in.Credentials[n].Payload))
		if e != nil {
			cancel()
			return nil, e
		}
		h.keys = append(h.keys, keys[0])
		h.bindings = append(h.bindings, b.ID)
		h.users[b.ID] = &meter{}
	}
	if s.MultiUser {
		keys, e := wire.Keys(s.Method, module.Material(in.ServerCredentials[0].Payload))
		if e != nil {
			cancel()
			return nil, e
		}
		h.identity = keys[0]
	}
	protected, e := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if e != nil {
		cancel()
		return nil, e
	}
	h.protected = protected
	h.retire = retire
	prepared = true
	return h, nil
}

type shadowsocksHandle struct {
	retire            func()
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	protected         *underlay.Dialer
	endpoint          access.Endpoint
	inbound           identity.ID
	udp               bool
	keys              []*wire.Key
	identity          *wire.Key
	bindings          []identity.ID
	total             *meter
	users             map[identity.ID]*meter
	replay            *shadowsocksReplayState
	listener          net.Listener
	packet            net.PacketConn
	packetWriter      *packetio.Writer
	connections       map[net.Conn]bool
	sessions          map[shadowsocksAssociationID]*shadowsocksServerPacket
	workers           sync.WaitGroup
	done              chan struct{}
	started, closed   bool
	running, admitted atomic.Bool
}

func (h *shadowsocksHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "shadowsocks runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	addr := net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port))
	lc := net.ListenConfig{}
	l, e := lc.Listen(ctx, "tcp", addr)
	if e != nil {
		return h.startError(e)
	}
	var packet net.PacketConn
	if h.udp {
		packet, e = lc.ListenPacket(ctx, "udp", addr)
		if e != nil {
			l.Close()
			return h.startError(e)
		}
	}
	h.listener = l
	h.packet = packet
	h.started = true
	h.running.Store(true)
	h.workers.Add(1)
	go h.accept()
	if packet != nil {
		h.packetWriter = packetio.NewAddressWriter(h.ctx, func(b []byte, a net.Addr) error {
			_, err := packet.WriteTo(b, a)
			return err
		})
		h.workers.Add(2)
		go h.receive()
		go h.expire()
	}
	return nil
}
func (*shadowsocksHandle) startError(e error) error {
	if addressInUse(e) {
		return identity.Err(identity.PortConflict, "shadowsocks listener port is already in use")
	}
	return identity.Err(identity.Unavailable, "shadowsocks listener start failed")
}
func (h *shadowsocksHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "shadowsocks listener unhealthy")
	}
	return nil
}
func (h *shadowsocksHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *shadowsocksHandle) Stats() ports.Stats { return h.total.snapshot() }
func (h *shadowsocksHandle) BindingStats(id identity.ID) ports.Stats {
	if m := h.users[id]; m != nil {
		return m.snapshot()
	}
	return ports.Stats{}
}
func (h *shadowsocksHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	first := !h.closed
	h.closed = true
	h.mu.Unlock()
	if first {
		h.admitted.Store(false)
		h.running.Store(false)
		h.cancel()
		go func() {
			if h.listener != nil {
				h.listener.Close()
			}
			if h.packet != nil {
				h.packet.Close()
				h.packetWriter.Wait()
			}
			h.mu.Lock()
			all := make([]io.Closer, 0, len(h.connections)+len(h.sessions))
			for c := range h.connections {
				all = append(all, c)
			}
			for _, s := range h.sessions {
				all = append(all, s)
			}
			h.mu.Unlock()
			for _, c := range all {
				c.Close()
			}
			h.workers.Wait()
			h.retire()
			close(h.done)
		}()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "shadowsocks shutdown timed out")
	}
}
func (h *shadowsocksHandle) accept() {
	defer h.workers.Done()
	for {
		c, e := h.listener.Accept()
		if e != nil {
			h.running.Store(false)
			return
		}
		h.mu.Lock()
		if h.closed || !h.admitted.Load() || len(h.connections) >= 256 {
			h.mu.Unlock()
			c.Close()
			continue
		}
		h.connections[c] = true
		h.workers.Add(1)
		h.mu.Unlock()
		go h.serve(c)
	}
}
func (h *shadowsocksHandle) serve(raw net.Conn) {
	defer h.workers.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.connections, raw); h.mu.Unlock() }()
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	c, dst, user, e := wire.AcceptTCP(raw, h.keys, h.identity, h.replay.salts, time.Now())
	if e != nil {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		return
	}
	_ = raw.SetReadDeadline(time.Time{})
	if !h.admitted.Load() {
		return
	}
	id := h.bindings[user]
	counted := meteredConn(c, h.total, h.users[id])
	defer counted.Close()
	remote, e := h.protected.DialContext(h.ctx, "tcp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	if e != nil {
		return
	}
	defer remote.Close()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.connections[remote] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.connections, remote); h.mu.Unlock() }()
	relay.Join(h.ctx, counted, remote)
}
