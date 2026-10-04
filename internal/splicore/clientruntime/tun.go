package clientruntime

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type tunIngress struct {
	manager *Manager
	spec    client.LocalInbound
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex // only generation acquisition and control, never payload I/O
	staged  *snapshot
	stopped bool
	stack   tun.Stack
	lease   *hostnetwork.Lease
}

func newTUNIngress(m *Manager, spec client.LocalInbound, gen *snapshot) *tunIngress {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunIngress{manager: m, spec: spec, ctx: ctx, cancel: cancel, staged: gen}
}
func (h *tunIngress) start(device tun.Tun) error {
	options := tun.Options{Name: h.spec.TUN.Interface, MTU: h.spec.TUN.MTU, DNSMode: tun.DNSModeDisabled, EXP_ExternalConfiguration: true}
	for _, raw := range h.spec.TUN.Addresses {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Addr().Is4() {
			options.Inet4Address = append(options.Inet4Address, prefix)
		} else {
			options.Inet6Address = append(options.Inet6Address, prefix)
		}
	}
	stack, err := startOwnedStack(tun.StackOptions{Context: h.ctx, Tun: device, TunOptions: options, UDPTimeout: h.manager.udpIdle, ICMPTimeout: 30 * time.Second, UDPNATMax: 4096, Handler: h, Logger: log.NewNOPFactory().Logger()})
	if err != nil {
		return err
	}
	h.stack = stack
	return nil
}
func (h *tunIngress) stop() {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.stopped = true
	h.staged = nil
	h.mu.Unlock()
	h.cancel()
	if h.stack != nil {
		_ = h.stack.Close()
	}
}
func (h *tunIngress) activate() { h.mu.Lock(); h.staged = nil; h.mu.Unlock() }
func (h *tunIngress) acquire() *snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.stopped {
		return nil
	}
	if h.staged != nil {
		h.staged.refs.Add(1)
		return h.staged
	}
	return h.manager.acquire()
}
func (h *tunIngress) JudgeFlow(network uint8, source, destination netip.AddrPort, first []byte) tun.FlowVerdict {
	if h.ctx.Err() != nil {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	if network == 17 && destination.Port() == 53 && h.spec.TUN.DNSHijack {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	if network != 6 && network != 17 {
		return tun.FlowVerdict{Action: tun.ActionReject}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}
func (m *Manager) registerFlow(parent context.Context, inbound identity.ID, c net.Conn, packet io.Closer) (context.Context, *session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || parent.Err() != nil || len(m.sessions) >= 4096 {
		return nil, nil
	}
	id, err := identity.NewID()
	if err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(parent)
	s := &session{id: id, inbound: inbound, local: c, packetLocal: packet, cancel: cancel}
	if c != nil {
		s.kind = "tcp"
	} else if packet != nil {
		s.kind = "tun_udp"
	} else {
		s.kind = "dns"
	}
	m.sessions[id] = s
	m.wg.Add(1)
	return ctx, s
}
func (m *Manager) finishFlow(s *session, gen *snapshot) {
	m.closeSession(s)
	gen.release()
	m.mu.Lock()
	delete(m.sessions, s.id)
	close(m.changed)
	m.changed = make(chan struct{})
	m.mu.Unlock()
	m.wg.Done()
}
func (h *tunIngress) NewConnectionEx(ctx context.Context, c net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	gen := h.acquire()
	if gen == nil {
		c.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	flowCtx, s := h.manager.registerFlow(ctx, h.spec.ID, c, nil)
	if s == nil {
		gen.release()
		c.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	go func() {
		defer h.manager.finishFlow(s, gen)
		if onClose != nil {
			defer onClose(nil)
		}
		stop := context.AfterFunc(flowCtx, func() { h.manager.closeSession(s) })
		defer stop()
		target := access.Endpoint{Host: destination.AddrString(), Port: destination.Port}
		if destination.Port == 53 && h.spec.TUN.DNSHijack {
			h.serveDNSStream(flowCtx, c, gen)
			return
		}
		h.manager.serveStream(flowCtx, s, gen, target, c, func(byte) {}, func() error { return nil })
	}()
}
func (h *tunIngress) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	gen := h.acquire()
	if gen == nil {
		c.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	flowCtx, s := h.manager.registerFlow(ctx, h.spec.ID, nil, c)
	if s == nil {
		gen.release()
		c.Close()
		if onClose != nil {
			onClose(net.ErrClosed)
		}
		return
	}
	go func() {
		defer h.manager.finishFlow(s, gen)
		if onClose != nil {
			defer onClose(nil)
		}
		stop := context.AfterFunc(flowCtx, func() { h.manager.closeSession(s) })
		defer stop()
		h.servePacket(flowCtx, s, gen, c, destination)
	}()
}
func (h *tunIngress) servePacket(ctx context.Context, s *session, gen *snapshot, local N.PacketConn, destination M.Socksaddr) {
	target := access.Endpoint{Host: destination.AddrString(), Port: destination.Port}
	decision, resolved, err := selectRoute(ctx, gen, s.inbound, target, "udp", map[identity.ID]P.Action{})
	if err != nil || decision.Selected.Kind == P.Reject {
		return
	}
	oid := selectedOutbound(decision.Selected)
	health, ok := gen.outbounds[oid].(*dialerLease)
	if !ok {
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	remote, err := health.ListenPacket(dialCtx, resolved)
	cancel()
	if err != nil {
		health.failed()
		return
	}
	defer remote.Close()
	counters := h.manager.bindSelection(s, gen, oid)
	h.manager.mu.Lock()
	s.kind = "tun_udp"
	s.packet = remote
	h.manager.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	for _, c := range counters {
		if c != nil {
			c.udpTotal.Add(1)
			c.udpActive.Add(1)
			defer c.udpActive.Add(-1)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer local.Close()
		payload := make([]byte, 65535)
		for {
			remote.SetReadDeadline(time.Now().Add(h.manager.udpIdle))
			n, _, e := remote.ReadFrom(payload)
			if e != nil {
				return
			}
			b := buf.As(append([]byte(nil), payload[:n]...))
			local.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if e = local.WritePacket(b, destination); e != nil {
				return
			}
			health.success()
			for _, c := range counters {
				if c != nil {
					c.download.Add(int64(n))
					c.packetsDown.Add(1)
				}
			}
		}
	}()
	defer func() { remote.Close(); local.Close(); <-done }()
	b := buf.NewSize(65535)
	defer b.Release()
	for {
		b.Reset()
		local.SetReadDeadline(time.Now().Add(h.manager.udpIdle))
		addr, e := local.ReadPacket(b)
		if e != nil {
			return
		}
		if addr != destination {
			return
		} // each upstream NAT flow owns one destination
		remote.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, e := remote.WriteTo(b.Bytes(), M.ParseSocksaddrHostPort(resolved.Host, resolved.Port))
		if e != nil {
			health.failed()
			return
		}
		n = min(n, b.Len())
		for _, c := range counters {
			if c != nil {
				c.upload.Add(int64(n))
				c.packetsUp.Add(1)
			}
		}
	}
}
func (h *tunIngress) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	// Upstream owns payload scratch memory. Copy before leaving its callback.
	request := append([]byte(nil), payload...)
	gen := h.acquire()
	if gen == nil {
		return
	}
	ctx, s := h.manager.registerFlow(h.ctx, h.spec.ID, nil, nil)
	if s == nil {
		gen.release()
		return
	}
	go func() {
		defer h.manager.finishFlow(s, gen)
		reply, err := gen.network.ExchangeDNS(ctx, request, false)
		if err != nil {
			return
		}
		_ = writer.WritePacket(buf.As(reply), destination)
	}()
}
func (h *tunIngress) serveDNSStream(ctx context.Context, c net.Conn, gen *snapshot) {
	var header [2]byte
	for {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(header[:]))
		if n < 12 {
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			return
		}
		reply, err := gen.network.ExchangeDNS(ctx, payload, true)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(header[:], uint16(len(reply)))
		if _, err = c.Write(append(header[:], reply...)); err != nil {
			return
		}
	}
}
