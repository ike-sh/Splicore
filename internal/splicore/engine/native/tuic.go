package native

import (
	"context"
	"crypto/tls"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/tuic/backend"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type TUICCompiler struct{}

func (TUICCompiler) ProtocolID() string { return "tuic" }
func (TUICCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c TUICCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	settings, _ := module.Decode(in.Inbound.Settings.Data)
	cert, key, err := tlsSnapshot(settings.TLS)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid TUIC TLS snapshot")
	}
	protected, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &tuicHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: protected, total: &traffic.Counter{}, users: map[string]*traffic.Counter{}, credentials: map[[16]byte]backend.User{}, tls: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		p := in.Credentials[i].Payload.(access.UUIDPasswordPayload)
		u, _ := uuid.FromString(p.UUID.Reveal())
		h.credentials[[16]byte(u)] = backend.User{ID: id, Password: p.Password.Reveal()}
	}
	return h, nil
}

type tuicHandle struct {
	lifecycle         sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	tls               *tls.Config
	server            *backend.Server
	started, closed   bool
	admitted, running atomic.Bool
	total             *traffic.Counter
	users             map[string]*traffic.Counter
	credentials       map[[16]byte]backend.User
}

func (h *tuicHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "TUIC runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "UDP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "TUIC listener start failed")
	}
	h.server, err = backend.NewServer(h.ctx, &admissionPacket{PacketConn: packet, h: h}, backend.ServerConfig{TLS: h.tls, Authenticate: h.authenticate, TCP: h.tcp, UDP: h.udp})
	if err != nil {
		_ = packet.Close()
		return identity.Err(identity.Unavailable, "TUIC construction failed")
	}
	h.started = true
	h.running.Store(true)
	h.server.Start()
	return nil
}
func (h *tuicHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *tuicHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "TUIC listener is not healthy")
	}
	return nil
}
func (h *tuicHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *tuicHandle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}
func (h *tuicHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.closed = true
	h.admitted.Store(false)
	h.running.Store(false)
	if h.cancel != nil {
		h.cancel()
	}
	server := h.server
	h.lifecycle.Unlock()
	if server != nil {
		if err := server.Close(ctx); err != nil {
			return identity.Err(identity.Unavailable, "TUIC shutdown timed out")
		}
	}
	return nil
}
func (h *tuicHandle) packetsAdmitted() bool { return h.admitted.Load() }
func (h *tuicHandle) packetsStopped()       { h.running.Store(false) }
func (h *tuicHandle) authenticate(id [16]byte) (backend.User, bool) {
	if !h.admitted.Load() {
		return backend.User{}, false
	}
	u, ok := h.credentials[id]
	return u, ok
}
func (h *tuicHandle) tcp(ctx context.Context, id string, c net.Conn, dst access.Endpoint) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	target, err := h.protected.DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	if err != nil {
		return err
	}
	defer target.Close()
	counted := traffic.Conn(c, h.total, user)
	defer counted.Close()
	relay.Join(ctx, counted, target)
	return nil
}
func (h *tuicHandle) udp(ctx context.Context, id string, p net.PacketConn) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	counted := traffic.Packet(p, h.total, user)
	defer counted.Close()
	return relay.Packets(ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
		return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	}, 5*time.Second)
}
