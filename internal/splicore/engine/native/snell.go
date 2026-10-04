// Package native composes unmodified sing-box constructors with owned lifecycle.
package native

import (
	"context"
	"errors"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"net"
	"strconv"
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
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	upstream "github.com/sagernet/sing-box/protocol/snell"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type SnellCompiler struct{}

func (SnellCompiler) ProtocolID() string { return "snell" }
func (SnellCompiler) Supports(i ports.RuntimeIntent) error {
	s, e := module.Decode(i.Inbound.Settings.Data)
	if e != nil {
		return e
	}
	_, e = (module.Module{Version: s.Version}).BuildRuntime(context.Background(), i)
	return e
}
func (e SnellCompiler) Compile(ctx context.Context, i ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := e.Supports(i); err != nil {
		return nil, err
	}
	s, _ := module.Decode(i.Inbound.Settings.Data)
	h := &Handle{connections: make(map[*rawConn]bool), endpoint: i.Inbound.Listeners[0].Endpoint, done: make(chan struct{})}
	// Runtime lifetime is independent of a canceled apply request. The coordinator owns Close.
	if _, err := underlay.FromContext(ctx); err != nil {
		return nil, err
	}
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	h.cancel = cancel
	ir := inbound.NewRegistry()
	inbound.Register[option.SnellInboundOptions](ir, "snell", func(ctx context.Context, r adapter.Router, l log.ContextLogger, tag string, o option.SnellInboundOptions) (adapter.Inbound, error) {
		stock, err := upstream.NewInbound(ctx, r, l, tag, o)
		if err != nil {
			return nil, err
		}
		h.stock = stock
		h.handler = stock.(adapter.ConnectionHandler)
		h.ctx = ctx
		return &ownedInbound{Inbound: stock, h: h}, nil
	})
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, ir, protectedOutbounds{or, underlay.ServerTarget}, endpoint.NewRegistry(), protectedDNS{dr}, boxservice.NewRegistry(), certificate.NewRegistry())
	psk := i.Credentials[0].Payload.(access.PSKPayload).Key.Reveal()
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{{Type: "local", Tag: "local", Options: &option.LocalDNSServerOptions{}}}}}, Outbounds: []option.Outbound{{Type: "direct", Tag: "protected-direct", Options: &option.DirectOutboundOptions{}}}, Route: &option.RouteOptions{Final: "protected-direct", DefaultDomainResolver: &option.DomainResolveOptions{Server: "local"}}, Log: &option.LogOptions{Disabled: true}, Inbounds: []option.Inbound{{Type: "snell", Tag: string(i.Inbound.ID), Options: &option.SnellInboundOptions{Version: s.Version, AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{PSK: psk}}}}}})
	if err != nil {
		cancel()
		if h.stock != nil {
			_ = h.stock.Close()
		}
		return nil, identity.Err(identity.Unavailable, "native runtime construction failed")
	}
	h.box = b
	b.Router().AppendTracker(h)
	return h, nil
}

type Handle struct {
	lifecycle   sync.Mutex
	box         *box.Box
	stock       adapter.Inbound
	handler     adapter.ConnectionHandler
	ctx         context.Context
	cancel      context.CancelFunc
	endpoint    access.Endpoint
	mu          sync.Mutex
	listener    net.Listener
	connections map[*rawConn]bool
	wg          sync.WaitGroup
	done        chan struct{}
	running     atomic.Bool
	admitted    atomic.Bool
	closed      bool
	started     bool
	upload      atomic.Int64
	download    atomic.Int64
	sessions    atomic.Int64
	active      atomic.Int64
}

func (h *Handle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "runtime start canceled")
	}
	h.mu.Lock()
	closed, started := h.closed, h.started
	h.mu.Unlock()
	if closed {
		return identity.Err(identity.Unavailable, "runtime closed")
	}
	if started {
		return nil
	}
	if err := h.box.Start(); err != nil {
		var de *identity.Error
		if errors.As(err, &de) && de.Code == identity.PortConflict {
			return identity.Err(identity.PortConflict, "listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "native runtime start failed; listener port may be in use")
	}
	h.mu.Lock()
	h.started = true
	h.mu.Unlock()
	return nil
}
func (h *Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "native listener is not healthy")
	}
	return nil
}
func (h *Handle) Activate() { h.admitted.Store(true) }
func (h *Handle) Stats() ports.Stats {
	return ports.Stats{Upload: h.upload.Load(), Download: h.download.Load(), Sessions: h.sessions.Load(), Active: h.active.Load()}
}
func (h *Handle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	if h.closed {
		done := h.done
		h.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return identity.Err(identity.Unavailable, "runtime shutdown timed out")
		}
	}
	h.closed = true
	h.admitted.Store(false)
	h.mu.Unlock()
	h.cancel()
	_ = h.box.Close()
	go func() { h.wg.Wait(); close(h.done) }()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "runtime shutdown timed out")
	}
}

type ownedInbound struct {
	adapter.Inbound
	h *Handle
}

func (o *ownedInbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	l, err := net.Listen("tcp", net.JoinHostPort(o.h.endpoint.Host, portString(o.h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "listener port is already in use")
		}
		return err
	}
	o.h.listener = l
	o.h.running.Store(true)
	o.h.wg.Add(1)
	go o.h.accept()
	return nil
}
func portString(p uint16) string { return strconv.Itoa(int(p)) }
func (o *ownedInbound) Close() error {
	h := o.h
	h.running.Store(false)
	if h.listener != nil {
		_ = h.listener.Close()
	}
	h.mu.Lock()
	conns := make([]*rawConn, 0, len(h.connections))
	for c := range h.connections {
		conns = append(conns, c)
	}
	h.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return h.stock.Close()
}
func (h *Handle) accept() {
	defer h.wg.Done()
	defer h.running.Store(false)
	for {
		c, e := h.listener.Accept()
		if e != nil {
			return
		}
		h.mu.Lock()
		if h.closed || !h.admitted.Load() {
			h.mu.Unlock()
			_ = c.Close()
			continue
		}
		raw := &rawConn{Conn: c, h: h}
		h.connections[raw] = true
		h.wg.Add(1)
		h.mu.Unlock()
		// Bound unauthenticated sockets. Authenticated routes clear this deadline below.
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		go func() {
			defer h.wg.Done()
			h.handler.NewConnection(h.ctx, raw, adapter.InboundContext{Source: M.SocksaddrFromNet(c.RemoteAddr())}, func(error) { _ = raw.Close() })
		}()
	}
}

type rawConn struct {
	net.Conn
	h    *Handle
	once sync.Once
}

func (c *rawConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.h.mu.Lock(); delete(c.h.connections, c); c.h.mu.Unlock() })
	return e
}
func (h *Handle) RoutedConnection(_ context.Context, c net.Conn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	_ = c.SetDeadline(time.Time{})
	h.sessions.Add(1)
	h.active.Add(1)
	return &countConn{ExtendedConn: bufio.NewInt64CounterConn(c, []*atomic.Int64{&h.upload}, []*atomic.Int64{&h.download}), h: h}
}

type countConn struct {
	N.ExtendedConn
	h    *Handle
	once sync.Once
}

func (c *countConn) Close() error {
	c.once.Do(func() { c.h.active.Add(-1) })
	return c.ExtendedConn.Close()
}
func (c *countConn) Upstream() any           { return c.ExtendedConn }
func (c *countConn) ReaderReplaceable() bool { return true }
func (c *countConn) WriterReplaceable() bool { return true }
func (h *Handle) RoutedPacketConnection(_ context.Context, c N.PacketConn, _ adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	_ = c.SetDeadline(time.Time{})
	h.sessions.Add(1)
	h.active.Add(1)
	return &countPacket{PacketConn: bufio.NewInt64CounterPacketConn(c, []*atomic.Int64{&h.upload}, nil, []*atomic.Int64{&h.download}, nil), h: h}
}

type countPacket struct {
	N.PacketConn
	h    *Handle
	once sync.Once
}

func (c *countPacket) Close() error {
	c.once.Do(func() { c.h.active.Add(-1) })
	return c.PacketConn.Close()
}
func (c *countPacket) Upstream() any           { return c.PacketConn }
func (c *countPacket) ReaderReplaceable() bool { return true }
func (c *countPacket) WriterReplaceable() bool { return true }
func (h *Handle) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}
