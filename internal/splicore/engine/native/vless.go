package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type VLESSCompiler struct{}

func (VLESSCompiler) ProtocolID() string { return "vless" }
func (VLESSCompiler) Supports(in ports.RuntimeIntent) error {
	s, err := module.Decode(in.Inbound.Settings.Data)
	if err != nil {
		return err
	}
	if in.Inbound.Engine != "native" {
		return identity.Err(identity.Invalid, "engine binding mismatch")
	}
	if s.Security == module.Reality && !module.RealityCompiled {
		return identity.Err(identity.NotImplemented, "REALITY requires with_utls")
	}
	_, err = (module.Module{Security: s.Security}).BuildRuntime(context.Background(), in)
	return err
}
func (c VLESSCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	var flow struct {
		Flow module.Flow `json:"flow"`
	}
	if json.Unmarshal(in.Inbound.Settings.Data, &flow) != nil {
		return nil, identity.Err(identity.Invalid, "invalid VLESS runtime settings")
	}
	if err := module.ValidateFlow(flow.Flow); err != nil {
		return nil, err
	}
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	dialer, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &vlessHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: dialer, total: &traffic.Counter{}, users: map[string]*traffic.Counter{}, uuids: map[[16]byte]string{}, connections: map[net.Conn]bool{}, done: make(chan struct{})}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		u, _ := uuid.FromString(in.Credentials[i].Payload.(access.UUIDPayload).UUID.Reveal())
		h.uuids[[16]byte(u)] = id
	}
	if s.Security == module.TLS {
		cert, key, err := tlsSnapshot(*s.TLS)
		if err != nil {
			cancel()
			return nil, err
		}
		defer clear(key)
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			cancel()
			return nil, identity.Err(identity.Invalid, "invalid VLESS TLS snapshot")
		}
		tc := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
		h.handshake = func(ctx context.Context, c net.Conn) (net.Conn, error) {
			tlsConn := tls.Server(c, tc)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tlsConn, nil
		}
	}
	if s.Security == module.Reality {
		ids := make([]string, len(s.Reality.ShortIDs))
		for i, id := range s.Reality.ShortIDs {
			ids[i] = string(id)
		}
		h.handshake, err = backend.RealityServer(s.Reality.ServerName, in.ServerCredentials[0].Payload.(access.PrivateKeyPayload).Material.Reveal(), ids, s.Reality.Target, dialer.DialContext)
		if err != nil {
			cancel()
			return nil, identity.Err(identity.Invalid, "invalid REALITY settings")
		}
		target := net.JoinHostPort(s.Reality.Target.Host, portString(s.Reality.Target.Port))
		h.targetProbe = func(ctx context.Context) error {
			c, err := dialer.DialContext(ctx, "tcp", target)
			if err == nil {
				_ = c.Close()
			}
			return err
		}
	}
	return h, nil
}

type vlessHandle struct {
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	handshake         func(context.Context, net.Conn) (net.Conn, error)
	targetProbe       func(context.Context) error
	listener          net.Listener
	connections       map[net.Conn]bool
	wg                sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
	total             *traffic.Counter
	users             map[string]*traffic.Counter
	uuids             map[[16]byte]string
}

func (h *vlessHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "VLESS runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	if h.targetProbe != nil {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := h.targetProbe(probe)
		cancel()
		if err != nil {
			return identity.Err(identity.Unavailable, "REALITY target is unavailable")
		}
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "VLESS listener start failed")
	}
	h.listener = l
	h.running.Store(true)
	h.started = true
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (h *vlessHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "VLESS listener is not healthy")
	}
	return nil
}
func (h *vlessHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *vlessHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *vlessHandle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}
func (h *vlessHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.admitted.Store(false)
		h.running.Store(false)
		connections := make([]net.Conn, 0, len(h.connections))
		for c := range h.connections {
			connections = append(connections, c)
		}
		h.mu.Unlock()
		if h.cancel != nil {
			h.cancel()
		}
		if h.listener != nil {
			_ = h.listener.Close()
		}
		for _, c := range connections {
			_ = c.Close()
		}
		go func() { h.wg.Wait(); close(h.done) }()
	} else {
		h.mu.Unlock()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "VLESS shutdown timed out")
	}
}
func (h *vlessHandle) accept() {
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
func (h *vlessHandle) serve(raw net.Conn) {
	defer h.wg.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.connections, raw); h.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	var c net.Conn = raw
	if h.handshake != nil {
		var err error
		c, err = h.handshake(h.ctx, raw)
		if err != nil {
			return
		}
		defer c.Close()
	}
	request, err := wire.ReadRequest(c)
	if err != nil {
		return
	}
	id, ok := h.uuids[request.UUID]
	if !ok || !h.admitted.Load() {
		return
	}
	user := h.users[id]
	_ = c.SetDeadline(time.Time{})
	stream := &backend.Conn{Conn: c, Server: true}
	if request.Command == wire.TCP {
		target, err := h.protected.DialContext(h.ctx, "tcp", net.JoinHostPort(request.Destination.Host, portString(request.Destination.Port)))
		if err != nil {
			return
		}
		defer target.Close()
		counted := traffic.Conn(stream, h.total, user)
		defer counted.Close()
		relay.Join(h.ctx, counted, target)
		return
	}
	_ = backend.Packets(h.ctx, stream, request, func(ctx context.Context, p net.PacketConn) error {
		counted := traffic.Packet(p, h.total, user)
		defer counted.Close()
		return relay.Packets(ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
			return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
		}, 5*time.Second)
	})
}
