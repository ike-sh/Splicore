package native

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/shadowquic/session"
)

type ShadowQUICCompiler struct{}

func (ShadowQUICCompiler) ProtocolID() string { return "shadowquic" }
func (ShadowQUICCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}

func (c ShadowQUICCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	settings, _ := module.Decode(in.Inbound.Settings.Data)
	protected, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	camouflage := settings.Camouflage
	if lookup := underlay.BootstrapFrom(ctx); lookup != nil {
		if _, err := netip.ParseAddr(camouflage.Host); err != nil {
			query, cancel := context.WithTimeout(ctx, settings.Limits.Handshake())
			ips, err := lookup(query, camouflage.Host)
			cancel()
			if err != nil {
				return nil, err
			}
			_, err = underlay.Normalize(ips)
			if err != nil {
				return nil, err
			}
			camouflage.Host = ips[0].Unmap().String()
		}
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	socket, err := clientconfig.PacketSocket(underlay.WithPurpose(ctx, underlay.ProxyUnderlay), camouflage)
	if err != nil {
		cancel()
		return nil, err
	}
	h := &shadowQUICHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: protected, total: &traffic.Counter{}, users: map[string]*traffic.Counter{}, settings: settings, lookup: underlay.TargetLookupFrom(ctx)}
	h.config = session.ServerConfig{ServerName: settings.ServerName, Camouflage: module.Address(settings.Camouflage), Limits: settings.Limits, Authorize: h.authorize, TCP: h.tcp, UDP: h.udp, PacketDialer: func(ctx context.Context, network, address string) (net.PacketConn, net.Addr, error) {
		if network != "udp" || address != module.Address(settings.Camouflage) {
			return nil, nil, session.ErrProtocol
		}
		return socket(ctx)
	}}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		p, _ := module.Pair(in.Credentials[i].Payload)
		h.config.Users = append(h.config.Users, session.User{ID: id, Username: p.Username.Reveal(), Password: p.Password.Reveal()})
	}
	return h, nil
}

type shadowQUICHandle struct {
	lifecycle         sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	lookup            underlay.HostLookup
	config            session.ServerConfig
	settings          module.Settings
	server            *session.Server
	started, closed   bool
	admitted, running atomic.Bool
	total             *traffic.Counter
	users             map[string]*traffic.Counter
}

func (h *shadowQUICHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "ShadowQUIC runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "UDP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "ShadowQUIC listener start failed")
	}
	h.server, err = session.NewServer(h.ctx, &admissionPacket{PacketConn: packet, h: h}, h.config)
	if err != nil {
		_ = packet.Close()
		return identity.Err(identity.Unavailable, "ShadowQUIC construction failed")
	}
	h.started = true
	h.running.Store(true)
	return nil
}

func (h *shadowQUICHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}

func (h *shadowQUICHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "ShadowQUIC listener is not healthy")
	}
	return nil
}
func (h *shadowQUICHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *shadowQUICHandle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}

func (h *shadowQUICHandle) Close(ctx context.Context) error {
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
			return identity.Err(identity.Unavailable, "ShadowQUIC shutdown timed out")
		}
	}
	return nil
}
func (h *shadowQUICHandle) packetsAdmitted() bool    { return h.admitted.Load() }
func (h *shadowQUICHandle) packetsStopped()          { h.running.Store(false) }
func (h *shadowQUICHandle) authorize(id string) bool { return h.admitted.Load() && h.users[id] != nil }

func (h *shadowQUICHandle) tcp(ctx context.Context, id string, c net.Conn, dst access.Endpoint) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	dialCtx, cancel := context.WithTimeout(ctx, h.settings.Limits.Handshake())
	target, err := h.dialTarget(dialCtx, "tcp", dst)
	cancel()
	if err != nil {
		return err
	}
	defer target.Close()
	counted := traffic.Conn(c, h.total, user)
	defer counted.Close()
	relay.Join(ctx, counted, target)
	return nil
}

func (h *shadowQUICHandle) udp(ctx context.Context, id string, p net.PacketConn) error {
	user := h.users[id]
	if user == nil || !h.admitted.Load() {
		return net.ErrClosed
	}
	counted := traffic.Packet(p, h.total, user)
	defer counted.Close()
	return relay.Packets(ctx, counted, func(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
		dialCtx, cancel := context.WithTimeout(ctx, h.settings.Limits.Handshake())
		defer cancel()
		c, err := h.dialTarget(dialCtx, "udp", dst)
		if err != nil {
			return nil, err
		}
		return &shadowQUICTarget{Conn: c, original: netaddr.UDP(dst)}, nil
	}, h.settings.Limits.UDPIdle())
}

// Reply addresses retain the wire destination even when the target socket is numeric.
type shadowQUICTarget struct {
	net.Conn
	original net.Addr
}

func (c *shadowQUICTarget) RemoteAddr() net.Addr { return c.original }

func (h *shadowQUICHandle) dialTarget(ctx context.Context, network string, dst access.Endpoint) (net.Conn, error) {
	if h.lookup != nil {
		if _, err := netip.ParseAddr(dst.Host); err != nil {
			ips, err := h.lookup(ctx, dst.Host)
			if err != nil {
				return nil, err
			}
			_, err = underlay.Normalize(ips)
			if err != nil {
				return nil, err
			}
			dst.Host = ips[0].Unmap().String()
		}
	}
	return h.protected.DialContext(ctx, network, module.Address(dst))
}
