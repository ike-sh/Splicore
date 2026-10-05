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
	"github.com/sagernet/sing-box/internal/splicore/nativetun"
	M "github.com/sagernet/sing/common/metadata"
)

type tunIngress struct {
	manager *Manager
	spec    client.LocalInbound
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex // only generation acquisition and control, never payload I/O
	staged  *snapshot
	stopped bool
	stopErr error
	stack   *nativetun.Runtime
	lease   *hostnetwork.Lease
}

func newTUNIngress(m *Manager, spec client.LocalInbound, gen *snapshot) *tunIngress {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunIngress{manager: m, spec: spec, ctx: ctx, cancel: cancel, staged: gen}
}
func (h *tunIngress) start(device nativetun.Device) error {
	h.mu.Lock()
	if h.stopped || h.stack != nil {
		h.mu.Unlock()
		return net.ErrClosed
	}
	options := nativetun.Options{MTU: h.spec.TUN.MTU, Dispatcher: h}
	for _, raw := range h.spec.TUN.Addresses {
		options.Addresses = append(options.Addresses, netip.MustParsePrefix(raw).Addr())
	}
	stack, err := nativetun.New(h.ctx, device, options)
	if err != nil {
		h.mu.Unlock()
		return err
	}
	h.stack = stack
	h.mu.Unlock()
	return stack.Start()
}
func (h *tunIngress) stop() {
	h.mu.Lock()
	if h.stopped {
		stack := h.stack
		h.mu.Unlock()
		if stack != nil {
			err := stack.Close()
			h.mu.Lock()
			h.stopErr = err
			h.mu.Unlock()
		}
		return
	}
	h.stopped = true
	h.staged = nil
	stack := h.stack
	h.mu.Unlock()
	h.cancel()
	if stack != nil {
		err := stack.Close()
		h.mu.Lock()
		h.stopErr = err
		h.mu.Unlock()
	}
}

func (h *tunIngress) stopError() error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stopErr
}
func (h *tunIngress) running() bool {
	h.mu.RLock()
	stack := h.stack
	h.mu.RUnlock()
	return stack != nil && stack.State() == nativetun.Running
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

// A cancellation callback can still be closing an adapter-owned connection
// after its context is cancelled. Join it before releasing the flow snapshot.
func (m *Manager) closeFlowOnCancel(ctx context.Context, s *session) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		m.closeSession(s)
	})
	return func() {
		if !stop() {
			<-done
		}
	}
}
func (h *tunIngress) TCP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	gen := h.acquire()
	if gen == nil {
		c.Close()
		return
	}
	flowCtx, s := h.manager.registerFlow(ctx, h.spec.ID, c, nil)
	if s == nil {
		gen.release()
		c.Close()
		return
	}
	defer h.manager.finishFlow(s, gen)
	defer h.manager.closeFlowOnCancel(flowCtx, s)()
	target := access.Endpoint{Host: destination.Addr().String(), Port: destination.Port()}
	if destination.Port() == 53 && h.spec.TUN.DNSHijack {
		h.serveDNSStream(flowCtx, c, gen)
		return
	}
	h.manager.serveStream(flowCtx, s, gen, target, c, func(byte) {}, func() error { return nil })
}
func (h *tunIngress) UDP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	if destination.Port() == 53 && h.spec.TUN.DNSHijack {
		h.serveDNSPacket(ctx, c)
		return
	}
	gen := h.acquire()
	if gen == nil {
		c.Close()
		return
	}
	flowCtx, s := h.manager.registerFlow(ctx, h.spec.ID, nil, c)
	if s == nil {
		gen.release()
		c.Close()
		return
	}
	defer h.manager.finishFlow(s, gen)
	defer h.manager.closeFlowOnCancel(flowCtx, s)()
	h.servePacket(flowCtx, s, gen, c, destination)
}
func (h *tunIngress) servePacket(ctx context.Context, s *session, gen *snapshot, local net.Conn, destination netip.AddrPort) {
	target := access.Endpoint{Host: destination.Addr().String(), Port: destination.Port()}
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
			local.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, e = local.Write(payload[:n]); e != nil {
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
	payload := make([]byte, 65535)
	for {
		local.SetReadDeadline(time.Now().Add(h.manager.udpIdle))
		size, e := local.Read(payload)
		if e != nil {
			return
		}
		remote.SetWriteDeadline(time.Now().Add(5 * time.Second))
		n, e := remote.WriteTo(payload[:size], M.ParseSocksaddrHostPort(resolved.Host, resolved.Port))
		if e != nil {
			health.failed()
			return
		}
		n = min(n, size)
		for _, c := range counters {
			if c != nil {
				c.upload.Add(int64(n))
				c.packetsUp.Add(1)
			}
		}
	}
}
func (h *tunIngress) serveDNSPacket(ctx context.Context, c net.Conn) {
	payload := make([]byte, 65535)
	for {
		_ = c.SetReadDeadline(time.Now().Add(h.manager.udpIdle))
		n, err := c.Read(payload)
		if err != nil {
			return
		}
		// Preserve stateless UDP DNS generation selection: the endpoint owns
		// packet affinity, but each query acquires the current DNS snapshot.
		gen := h.acquire()
		if gen == nil {
			return
		}
		err = func() error {
			flowCtx, s := h.manager.registerFlow(ctx, h.spec.ID, nil, nil)
			if s == nil {
				gen.release()
				return net.ErrClosed
			}
			defer h.manager.finishFlow(s, gen)
			reply, err := gen.network.ExchangeDNS(flowCtx, payload[:n], false)
			if err != nil {
				return err
			}
			_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = c.Write(reply)
			return err
		}()
		if err != nil {
			return
		}
	}
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
