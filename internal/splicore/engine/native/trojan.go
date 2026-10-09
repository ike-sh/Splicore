package native

import (
	"context"
	"crypto/tls"
	streamcfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trojan/backend"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

type TrojanCompiler struct{}

func (TrojanCompiler) ProtocolID() string { return "trojan" }
func (TrojanCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c TrojanCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	cert, key, err := tlsSnapshot(s.TLS)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid Trojan TLS snapshot")
	}
	d, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &trojanHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: d, tls: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: slices.Clone(s.ALPN)}, connections: map[net.Conn]bool{}, users: map[string]*traffic.Counter{}, total: &traffic.Counter{}, done: make(chan struct{})}
	if s.Stream != nil {
		h.transport = *s.Stream
	}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		h.keys = append(h.keys, wire.User{ID: id, Key: wire.Derive(in.Credentials[i].Payload.(access.PasswordPayload).Password)})
	}
	return h, nil
}

type trojanHandle struct {
	transport         streamcfg.Config
	transportTLS      *tls.Config
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	tls               *tls.Config
	listener          net.Listener
	connections       map[net.Conn]bool
	keys              []wire.User
	users             map[string]*traffic.Counter
	total             *traffic.Counter
	wg                sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
}

func (h *trojanHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "Trojan runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "Trojan listener start failed")
	}
	if h.transport.Type() != "tcp" {
		wrapped, e := shared.WrapListener(l, h.transport, h.tls)
		if e != nil {
			l.Close()
			return e
		}
		l = wrapped
	}
	h.listener = l
	h.started = true
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (h *trojanHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *trojanHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "Trojan listener is not healthy")
	}
	return nil
}
func (h *trojanHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *trojanHandle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}
func (h *trojanHandle) Close(ctx context.Context) error {
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
		go func() {
			h.wg.Wait()
			for i := range h.keys {
				clear(h.keys[i].Key[:])
			}
			close(h.done)
		}()
	} else {
		h.mu.Unlock()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "Trojan shutdown timed out")
	}
}
func (h *trojanHandle) accept() {
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
func (h *trojanHandle) serve(raw net.Conn) {
	defer h.wg.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.connections, raw); h.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = raw
	if h.transport.Type() == "tcp" {
		t := tls.Server(raw, h.tls)
		if t.HandshakeContext(h.ctx) != nil {
			return
		}
		c = t
	}
	defer c.Close()
	r, err := wire.ReadRequest(c)
	if err != nil {
		return
	}
	id, valid := wire.Match(r.Key, h.keys)
	clear(r.Key[:])
	if !valid || !h.admitted.Load() {
		return
	}
	_ = c.SetDeadline(time.Time{})
	stream := &backend.Stream{Conn: c, Raw: raw}
	user := h.users[id]
	if r.Command == wire.Connect {
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
	packet := backend.NewPacket(h.ctx, stream)
	defer packet.Close()
	counted := traffic.Packet(packet, h.total, user)
	defer counted.Close()
	_ = relay.Packets(h.ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
		return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	}, 5*time.Second)
}
