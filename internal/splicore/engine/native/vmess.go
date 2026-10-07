package native

import (
	"context"
	"crypto/tls"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vmess/backend"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// VMessCompiler owns replay history across listener generation replacement.
// The bounded bank has no workers or timer and expires lazily on admission.
type VMessCompiler struct {
	replay *wire.Replay
	now    func() time.Time
}

func NewVMessCompiler() *VMessCompiler {
	return &VMessCompiler{replay: wire.NewReplay(65536), now: time.Now}
}
func (*VMessCompiler) ProtocolID() string { return "vmess" }
func (*VMessCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c *VMessCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if c == nil || c.replay == nil || c.now == nil {
		return nil, identity.Err(identity.Invalid, "VMess compiler is uninitialized")
	}
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	d, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	var tc *tls.Config
	if s.Security == "tls" {
		cert, key, err := tlsSnapshot(*s.TLS)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, identity.Err(identity.Invalid, "invalid VMess TLS snapshot")
		}
		tc = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: slices.Clone(s.ALPN)}
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &vmessHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: d, tls: tc, connections: map[net.Conn]bool{}, users: map[string]*traffic.Counter{}, total: &traffic.Counter{}, done: make(chan struct{}), replay: c.replay, now: c.now}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		h.keys = append(h.keys, wire.NewUser(id, module.CommandKey(in.Credentials[i].Payload.(access.UUIDPayload))))
	}
	return h, nil
}

type vmessHandle struct {
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	tls               *tls.Config
	listener          net.Listener
	connections       map[net.Conn]bool
	keys              []wire.User
	replay            *wire.Replay
	now               func() time.Time
	users             map[string]*traffic.Counter
	total             *traffic.Counter
	wg                sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
}

func (h *vmessHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "VMess runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "VMess listener start failed")
	}
	h.listener = l
	h.started = true
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (h *vmessHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *vmessHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "VMess listener is not healthy")
	}
	return nil
}
func (h *vmessHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *vmessHandle) BindingStats(id identity.ID) ports.Stats {
	if v := h.users[string(id)]; v != nil {
		return v.Snapshot()
	}
	return ports.Stats{}
}
func (h *vmessHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.admitted.Store(false)
		h.running.Store(false)
		all := make([]net.Conn, 0, len(h.connections))
		for c := range h.connections {
			all = append(all, c)
		}
		h.mu.Unlock()
		h.cancel()
		if h.listener != nil {
			_ = h.listener.Close()
		}
		for _, c := range all {
			_ = c.Close()
		}
		go func() { h.wg.Wait(); clear(h.keys); h.keys = nil; close(h.done) }()
	} else {
		h.mu.Unlock()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "VMess shutdown timed out")
	}
}
func (h *vmessHandle) accept() {
	defer h.wg.Done()
	defer h.running.Store(false)
	for {
		raw, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed || !h.admitted.Load() || len(h.connections) >= 512 {
			h.mu.Unlock()
			_ = raw.Close()
			continue
		}
		h.connections[raw] = true
		h.wg.Add(1)
		h.mu.Unlock()
		go h.serve(raw)
	}
}
func (h *vmessHandle) serve(raw net.Conn) {
	defer h.wg.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.connections, raw); h.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = raw
	if h.tls != nil {
		tc := tls.Server(raw, h.tls)
		if tc.HandshakeContext(h.ctx) != nil {
			return
		}
		c = tc
		defer tc.Close()
	}
	r, id, err := wire.ReadRequestWithClock(c, h.keys, h.replay, h.now)
	if err != nil || !h.admitted.Load() {
		return
	}
	_ = c.SetDeadline(time.Time{})
	stream, err := backend.Server(h.ctx, c, r)
	if err != nil {
		return
	}
	defer stream.Close()
	user := h.users[id]
	if r.Command == wire.TCP {
		target, err := h.protected.DialContext(h.ctx, "tcp", net.JoinHostPort(r.Destination.Host, portString(r.Destination.Port)))
		if err != nil {
			return
		}
		defer target.Close()
		counted := traffic.Conn(stream, h.total, user)
		defer counted.Close()
		relay.Join(h.ctx, counted, target)
		return
	}
	p := backend.NewPacket(h.ctx, stream, r.Destination)
	defer p.Close()
	counted := traffic.Packet(p, h.total, user)
	defer counted.Close()
	_ = relay.Packets(h.ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
		return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	}, 5*time.Second)
}
