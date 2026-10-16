package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/hysteria2/backend"
)

type Hysteria2Compiler struct{}
type Hysteria2Handle = hysteria2Handle

func (Hysteria2Compiler) ProtocolID() string { return "hysteria2" }
func (Hysteria2Compiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c Hysteria2Compiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
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
		return nil, identity.Err(identity.Invalid, "invalid Hysteria2 TLS snapshot")
	}
	dialer, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &hysteria2Handle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: dialer, total: &traffic.Counter{}, users: map[string]*traffic.Counter{}, passwords: map[[32]byte]string{}, tls: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}}
	h.transport = settings.Transport().HysteriaSettings()
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		password := in.Credentials[i].Payload.(access.PasswordPayload).Password.Reveal()
		h.passwords[sha256.Sum256([]byte(password))] = id
	}
	return h, nil
}

type hysteria2Handle struct {
	lifecycle         sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	tls               *tls.Config
	transport         cfg.Hysteria
	server            *backend.Server
	started, closed   bool
	running, admitted atomic.Bool
	total             *traffic.Counter
	users             map[string]*traffic.Counter
	passwords         map[[32]byte]string
}

func (h *hysteria2Handle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "Hysteria2 runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "UDP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "Hysteria2 listener start failed")
	}
	h.server, err = backend.NewServer(h.ctx, &admissionPacket{PacketConn: packet, h: h}, backend.ServerConfig{TLS: h.tls, Transport: h.transport, Authenticate: h.authenticate, TCP: h.tcp, UDP: h.udp})
	if err != nil {
		_ = packet.Close()
		return identity.Err(identity.Unavailable, "Hysteria2 construction failed")
	}
	h.started = true
	h.running.Store(true)
	h.server.Start()
	return nil
}
func (h *hysteria2Handle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *hysteria2Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "Hysteria2 listener is not healthy")
	}
	return nil
}
func (h *hysteria2Handle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *hysteria2Handle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}
func (h *hysteria2Handle) Close(ctx context.Context) error {
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
			return identity.Err(identity.Unavailable, "Hysteria2 shutdown timed out")
		}
	}
	return nil
}
func (h *hysteria2Handle) packetsAdmitted() bool { return h.admitted.Load() }
func (h *hysteria2Handle) packetsStopped()       { h.running.Store(false) }
func (h *hysteria2Handle) authenticate(password string) (string, bool) {
	if !h.admitted.Load() {
		return "", false
	}
	id, ok := h.passwords[sha256.Sum256([]byte(password))]
	return id, ok
}
func (h *hysteria2Handle) tcp(ctx context.Context, id string, c *backend.Stream, dst access.Endpoint) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	target, err := h.protected.DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	if err != nil {
		return err
	}
	defer target.Close()
	if err := c.Reply(true); err != nil {
		return err
	}
	counted := traffic.Conn(c, h.total, user)
	defer counted.Close()
	relay.Join(ctx, counted, target)
	return nil
}
func (h *hysteria2Handle) udp(ctx context.Context, id string, p net.PacketConn) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	counted := traffic.Packet(p, h.total, user)
	defer counted.Close()
	return relay.Packets(ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
		return h.protected.DialContext(ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	}, time.Duration(h.transport.IdleSeconds())*time.Second)
}
