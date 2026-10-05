package native

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"net"
	"sync"
	"sync/atomic"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/tlsconfig"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type udpService interface {
	Start(net.PacketConn) error
	Close() error
}
type udpFactory func(context.Context, log.ContextLogger, boxtls.ServerConfig, *quicHandle) (udpService, error)

func newQUICRuntime(ctx context.Context, in ports.RuntimeIntent, settings tlsconfig.Settings, factory udpFactory) (ports.PreparedRuntime, error) {
	cert, key, err := tlsSnapshot(settings)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	h := &quicHandle{protocol: in.Inbound.Protocol.Protocol, endpoint: in.Inbound.Listeners[0].Endpoint, inboundID: in.Inbound.ID, total: &meter{}, users: map[string]*meter{}}
	for _, b := range in.Bindings {
		h.users[string(b.ID)] = &meter{}
	}
	if _, err := underlay.FromContext(ctx); err != nil {
		return nil, err
	}
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h.cancel = cancel
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	ir := inbound.NewRegistry()
	inbound.Register[option.InboundTLSOptionsContainer](ir, h.protocol, func(ctx context.Context, r adapter.Router, l log.ContextLogger, tag string, o option.InboundTLSOptionsContainer) (adapter.Inbound, error) {
		h.router = r
		config, err := boxtls.NewServer(ctx, l, *o.TLS)
		if err != nil {
			return nil, err
		}
		h.tls = config
		h.service, err = factory(ctx, l, config, h)
		if err != nil {
			_ = config.Close()
			return nil, err
		}
		return &quicOwnedInbound{Adapter: inbound.NewAdapter(h.protocol, tag), h: h}, nil
	})
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, ir, protectedOutbounds{or, underlay.ServerTarget}, endpoint.NewRegistry(), protectedDNS{dr}, boxservice.NewRegistry(), certificate.NewRegistry())
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "local", Tag: "local", Options: &option.LocalDNSServerOptions{}}}}}, Outbounds: []option.Outbound{{Type: "direct", Tag: "protected-direct", Options: &option.DirectOutboundOptions{}}}, Route: &option.RouteOptions{Final: "protected-direct", DefaultDomainResolver: &option.DomainResolveOptions{Server: "local"}}, Log: &option.LogOptions{Disabled: true}, Inbounds: []option.Inbound{{Type: h.protocol, Tag: string(in.Inbound.ID), Options: &option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{Enabled: true, ServerName: settings.ServerName, Certificate: []string{string(cert)}, Key: []string{string(key)}, MinVersion: "1.3", ALPN: []string{"h3"}}}}}}})
	if err != nil {
		cancel()
		if h.service != nil {
			_ = h.service.Close()
		}
		if h.tls != nil {
			_ = h.tls.Close()
		}
		return nil, identity.Err(identity.Unavailable, "native QUIC construction failed")
	}
	h.box = b
	b.Router().AppendTracker(h)
	return h, nil
}

type quicHandle struct {
	protocol        string
	lifecycle       sync.Mutex
	box             *box.Box
	router          adapter.Router
	service         udpService
	tls             boxtls.ServerConfig
	endpoint        access.Endpoint
	inboundID       identity.ID
	packet          net.PacketConn
	cancel          context.CancelFunc
	admitted        atomic.Bool
	running         atomic.Bool
	started, closed bool
	total           *meter
	users           map[string]*meter
}

func (h *quicHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	if err := h.box.Start(); err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "UDP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "QUIC runtime start failed")
	}
	h.started = true
	return nil
}
func (h *quicHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "QUIC listener is not healthy")
	}
	return nil
}
func (h *quicHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *quicHandle) Stats() ports.Stats { return h.total.snapshot() }
func (h *quicHandle) BindingStats(id identity.ID) ports.Stats {
	if m := h.users[string(id)]; m != nil {
		return m.snapshot()
	}
	return ports.Stats{}
}
func (h *quicHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	wasAdmitted := h.admitted.Load()
	h.admitted.Store(false)
	h.running.Store(false)
	h.cancel()
	// The service sends connection-close frames from cancellation callbacks.
	// Keep the owned socket writable for a bounded grace interval before closing
	// its QUIC listener/transport. Otherwise peers can retain a dead cached session.
	if wasAdmitted && h.started {
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
	}
	if err := h.box.Close(); err != nil {
		return identity.Err(identity.Unavailable, "QUIC shutdown failed")
	}
	return nil
}

type quicOwnedInbound struct {
	inbound.Adapter
	h *quicHandle
}

func (o *quicOwnedInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h := o.h
	if err := h.tls.Start(); err != nil {
		return err
	}
	packet, err := net.ListenPacket("udp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		return err
	}
	h.packet = packet
	if err = h.service.Start(&admissionPacket{PacketConn: packet, h: h}); err != nil {
		_ = packet.Close()
		return err
	}
	h.running.Store(true)
	return nil
}
func (o *quicOwnedInbound) Close() error {
	h := o.h
	h.running.Store(false)
	if h.service != nil {
		_ = h.service.Close()
	}
	if h.packet != nil {
		_ = h.packet.Close()
	}
	if h.tls != nil {
		return h.tls.Close()
	}
	return nil
}

type admissionPacket struct {
	net.PacketConn
	h *quicHandle
}

func (p *admissionPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			p.h.running.Store(false)
			return n, a, err
		}
		if p.h.admitted.Load() {
			return n, a, nil
		}
	}
}
func (h *quicHandle) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		_ = c.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	h.router.RouteConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: h.protocol, User: user, Source: src, Destination: dst}, onClose)
}
func (h *quicHandle) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		_ = c.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	h.router.RoutePacketConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: h.protocol, User: user, Source: src, Destination: dst}, onClose)
}
func (h *quicHandle) RoutedConnection(_ context.Context, c net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	return meteredConn(c, h.total, h.users[m.User])
}
func (h *quicHandle) RoutedPacketConnection(_ context.Context, c N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return meteredPacket(c, h.total, h.users[m.User])
}
func (h *quicHandle) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}
