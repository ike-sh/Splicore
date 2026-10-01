package native

import (
	"context"
	"encoding/json"
	"errors"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-tun"
	upstream "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
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
	// Reject unsupported flow before Supports, TLS material access or construction.
	// Only the flow field is inspected here; full settings validation follows.
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
	tlsOptions := option.InboundTLSOptions{}
	if s.Security == module.TLS {
		cert, key, err := tlsSnapshot(*s.TLS)
		if err != nil {
			return nil, err
		}
		defer clear(key)
		tlsOptions = option.InboundTLSOptions{Enabled: true, ServerName: s.TLS.ServerName, Certificate: []string{string(cert)}, Key: []string{string(key)}, MinVersion: "1.3", HandshakeTimeout: badoption.Duration(5 * time.Second)}
	}
	if s.Security == module.Reality {
		ids := []string{}
		for _, id := range s.Reality.ShortIDs {
			ids = append(ids, string(id))
		}
		tlsOptions = option.InboundTLSOptions{Enabled: true, ServerName: s.Reality.ServerName, MinVersion: "1.3", HandshakeTimeout: badoption.Duration(5 * time.Second), Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: in.ServerCredentials[0].Payload.(access.PrivateKeyPayload).Material.Reveal(), ShortID: ids, Handshake: option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: s.Reality.Target.Host, ServerPort: s.Reality.Target.Port}}}}
	}
	h := &vlessHandle{endpoint: in.Inbound.Listeners[0].Endpoint, inboundID: in.Inbound.ID, total: &meter{}, users: map[string]*meter{}, connections: map[*vlessRaw]bool{}, done: make(chan struct{})}
	for _, b := range in.Bindings {
		h.users[string(b.ID)] = &meter{}
	}
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h.cancel = cancel
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	ir := inbound.NewRegistry()
	inbound.Register[option.InboundTLSOptionsContainer](ir, "vless", func(ctx context.Context, r adapter.Router, l log.ContextLogger, tag string, o option.InboundTLSOptionsContainer) (adapter.Inbound, error) {
		h.router = r
		h.ctx = ctx
		var err error
		if o.TLS != nil {
			h.tls, err = boxtls.NewServer(ctx, l, *o.TLS)
			if err != nil {
				return nil, err
			}
		}
		h.service = upstream.NewService[string](l, h)
		names, uuids, flows := []string{}, []string{}, []string{}
		for n, b := range in.Bindings {
			names = append(names, string(b.ID))
			uuids = append(uuids, in.Credentials[n].Payload.(access.UUIDPayload).UUID.Reveal())
			// Managed users are always flow-none. A Vision request is rejected by
			// upstream's flow mismatch check before its Vision constructor.
			flows = append(flows, "")
		}
		h.service.UpdateUsers(names, uuids, flows) // immutable after construction
		if s.Security == module.Reality {
			kind, _ := access.ParseHost(s.Reality.Target.Host)
			d, err := dialer.New(ctx, option.DialerOptions{}, kind == access.DNS)
			if err != nil {
				return nil, err
			}
			h.targetProbe = func(ctx context.Context) error {
				conn, err := d.DialContext(ctx, "tcp", M.ParseSocksaddr(net.JoinHostPort(s.Reality.Target.Host, portString(s.Reality.Target.Port))))
				if err == nil {
					_ = conn.Close()
				}
				return err
			}
		}
		return &vlessOwnedInbound{Adapter: inbound.NewAdapter("vless", tag), h: h}, nil
	})
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, ir, or, endpoint.NewRegistry(), dr, boxservice.NewRegistry(), certificate.NewRegistry())
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "local", Tag: "local", Options: &option.LocalDNSServerOptions{}}}}}, Route: &option.RouteOptions{DefaultDomainResolver: &option.DomainResolveOptions{Server: "local"}}, Log: &option.LogOptions{Disabled: true}, Inbounds: []option.Inbound{{Type: "vless", Tag: string(in.Inbound.ID), Options: &option.InboundTLSOptionsContainer{TLS: &tlsOptions}}}}})
	if err != nil {
		cancel()
		if h.tls != nil {
			_ = h.tls.Close()
		}
		return nil, identity.Err(identity.Unavailable, "native VLESS construction failed")
	}
	h.box = b
	b.Router().AppendTracker(h)
	return h, nil
}

type vlessHandle struct {
	lifecycle         sync.Mutex
	box               *box.Box
	router            adapter.Router
	service           *upstream.Service[string]
	tls               boxtls.ServerConfig
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	inboundID         identity.ID
	targetProbe       func(context.Context) error
	listener          net.Listener
	mu                sync.Mutex
	connections       map[*vlessRaw]bool
	wg                sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
	total             *meter
	users             map[string]*meter
}

func (h *vlessHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	if err := h.box.Start(); err != nil {
		var de *identity.Error
		if addressInUse(err) || errors.As(err, &de) && de.Code == identity.PortConflict {
			return identity.Err(identity.PortConflict, "TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "VLESS runtime start failed")
	}
	h.started = true
	return nil
}
func (h *vlessHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "VLESS listener is not healthy")
	}
	return nil
}
func (h *vlessHandle) Activate()          { h.admitted.Store(true) }
func (h *vlessHandle) Stats() ports.Stats { return h.total.snapshot() }
func (h *vlessHandle) BindingStats(id identity.ID) ports.Stats {
	if m := h.users[string(id)]; m != nil {
		return m.snapshot()
	}
	return ports.Stats{}
}
func (h *vlessHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.admitted.Store(false)
		h.running.Store(false)
		h.mu.Unlock()
		h.cancel()
		_ = h.box.Close()
		go func() { h.wg.Wait(); close(h.done) }()
	} else {
		h.mu.Unlock()
	}
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "VLESS shutdown timed out")
	}
}

type vlessOwnedInbound struct {
	inbound.Adapter
	h *vlessHandle
}

func (o *vlessOwnedInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h := o.h
	if h.tls != nil {
		if err := h.tls.Start(); err != nil {
			return err
		}
	}
	// Bounded reachability gate; target TLS compatibility is tested during handshake.
	if h.targetProbe != nil {
		ctx, cancel := context.WithTimeout(h.ctx, 2*time.Second)
		defer cancel()
		if err := h.targetProbe(ctx); err != nil {
			return identity.Err(identity.Unavailable, "REALITY target is unavailable")
		}
	}
	l, err := net.Listen("tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		return err
	}
	h.listener = l
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (o *vlessOwnedInbound) Close() error {
	h := o.h
	h.running.Store(false)
	if h.listener != nil {
		_ = h.listener.Close()
	}
	h.mu.Lock()
	connections := make([]*vlessRaw, 0, len(h.connections))
	for c := range h.connections {
		connections = append(connections, c)
	}
	h.mu.Unlock()
	for _, c := range connections {
		_ = c.Close()
	}
	if h.tls != nil {
		return h.tls.Close()
	}
	return nil
}
func (h *vlessHandle) accept() {
	defer h.wg.Done()
	defer h.running.Store(false)
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed || !h.admitted.Load() {
			h.mu.Unlock()
			_ = conn.Close()
			continue
		}
		raw := &vlessRaw{Conn: conn, h: h}
		h.connections[raw] = true
		h.wg.Add(2)
		h.mu.Unlock()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			defer h.wg.Done()
			var c net.Conn = raw
			if h.tls != nil {
				tlsConn, err := boxtls.ServerHandshake(h.ctx, raw, h.tls)
				if err != nil {
					_ = raw.Close()
					return
				}
				c = tlsConn
			}
			onClose := func(error) { _ = raw.Close() }
			if err := h.service.NewConnection(h.ctx, c, M.SocksaddrFromNet(raw.RemoteAddr()), onClose); err != nil {
				_ = raw.Close()
			}
		}()
	}
}

type vlessRaw struct {
	net.Conn
	h    *vlessHandle
	once sync.Once
}

func (c *vlessRaw) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.h.mu.Lock(); delete(c.h.connections, c); c.h.mu.Unlock(); c.h.wg.Done() })
	return err
}
func (h *vlessHandle) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		N.CloseOnHandshakeFailure(c, onClose, net.ErrClosed)
		return
	}
	_ = c.SetDeadline(time.Time{})
	h.router.RouteConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: "vless", User: user, Source: src, Destination: dst}, onClose)
}
func (h *vlessHandle) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		N.CloseOnHandshakeFailure(c, onClose, net.ErrClosed)
		return
	}
	_ = c.SetDeadline(time.Time{})
	h.router.RoutePacketConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: "vless", User: user, Source: src, Destination: dst}, onClose)
}
func (h *vlessHandle) RoutedConnection(_ context.Context, c net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	return meteredConn(c, h.total, h.users[m.User])
}
func (h *vlessHandle) RoutedPacketConnection(_ context.Context, c N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return meteredPacket(c, h.total, h.users[m.User])
}
func (h *vlessHandle) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}
