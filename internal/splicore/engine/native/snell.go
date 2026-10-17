package native

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
)

type SnellCompiler struct{}

func (SnellCompiler) ProtocolID() string { return "snell" }
func (SnellCompiler) Supports(in ports.RuntimeIntent) error {
	s, e := module.Decode(in.Inbound.Settings.Data)
	if e != nil {
		return e
	}
	_, e = (module.Module{Version: s.Version}).BuildRuntime(context.Background(), in)
	return e
}
func (f SnellCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if e := f.Supports(in); e != nil {
		return nil, e
	}
	d, e := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if e != nil {
		return nil, e
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	k, e := wire.NewKey(s.Version, in.Credentials[0].Payload.(access.PSKPayload).Key.Reveal())
	if e != nil {
		return nil, e
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	return &Handle{ctx: owned, cancel: cancel, protected: d, key: k, obfsHTTP: s.ObfsMode == "http", endpoint: in.Inbound.Listeners[0].Endpoint, total: &traffic.Counter{}, connections: map[net.Conn]bool{}, done: make(chan struct{})}, nil
}

// Handle owns listening, accepted and target sockets through shutdown join.
// Record state belongs to wire.Tunnel, never to the runtime's scratch space.
type Handle struct {
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	protected         *underlay.Dialer
	key               *wire.Key
	obfsHTTP          bool
	endpoint          access.Endpoint
	listener          net.Listener
	connections       map[net.Conn]bool
	wg                sync.WaitGroup
	done              chan struct{}
	total             *traffic.Counter
	closed, started   bool
	running, admitted atomic.Bool
}

func portString(p uint16) string { return strconv.Itoa(int(p)) }
func (h *Handle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "Snell runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	lc := net.ListenConfig{}
	l, e := lc.Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if e != nil {
		if addressInUse(e) {
			return identity.Err(identity.PortConflict, "listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "Snell listener start failed")
	}
	h.listener = l
	h.started = true
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (h *Handle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "Snell listener is not healthy")
	}
	return nil
}
func (h *Handle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *Handle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	first := !h.closed
	h.closed = true
	h.mu.Unlock()
	if first {
		h.admitted.Store(false)
		h.running.Store(false)
		h.cancel()
		if h.listener != nil {
			_ = h.listener.Close()
		}
		h.mu.Lock()
		all := make([]net.Conn, 0, len(h.connections))
		for c := range h.connections {
			all = append(all, c)
		}
		h.mu.Unlock()
		for _, c := range all {
			_ = c.Close()
		}
		go func() { h.wg.Wait(); close(h.done) }()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "Snell shutdown timed out")
	}
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
		if h.closed || !h.admitted.Load() || len(h.connections) >= 256 {
			h.mu.Unlock()
			_ = c.Close()
			continue
		}
		h.connections[c] = true
		h.wg.Add(1)
		h.mu.Unlock()
		go h.serve(c)
	}
}
func (h *Handle) addTarget(c net.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		_ = c.Close()
		return false
	}
	h.connections[c] = true
	return true
}
func (h *Handle) remove(c net.Conn) { h.mu.Lock(); delete(h.connections, c); h.mu.Unlock() }
func (h *Handle) serve(raw net.Conn) {
	defer h.wg.Done()
	defer raw.Close()
	defer h.remove(raw)
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	stream := raw
	if h.obfsHTTP {
		stream = wire.HTTPServer(raw)
	}
	_ = wire.Serve(stream, h.key, func(tunnel *wire.Tunnel, dst access.Endpoint) error {
		_ = raw.SetReadDeadline(time.Time{})
		if !h.admitted.Load() {
			return net.ErrClosed
		}
		target, e := h.protected.DialContext(h.ctx, "tcp", net.JoinHostPort(dst.Host, portString(dst.Port)))
		if e != nil {
			return e
		}
		if !h.addTarget(target) {
			return net.ErrClosed
		}
		defer h.remove(target)
		defer target.Close()
		counted := traffic.Conn(tunnel, h.total)
		defer counted.Close()
		relay.Join(h.ctx, counted, target)
		return nil
	}, func(packet *wire.Packet) error {
		_ = raw.SetReadDeadline(time.Time{})
		if !h.admitted.Load() {
			return net.ErrClosed
		}
		return h.serveUDP(packet)
	})
}
func (h *Handle) serveUDP(packet net.PacketConn) error {
	defer packet.Close()
	release := traffic.Open(false, h.total)
	defer release()
	targets := map[access.Endpoint]net.Conn{}
	var readers sync.WaitGroup
	defer func() {
		_ = packet.Close()
		for _, c := range targets {
			_ = c.Close()
		}
		readers.Wait()
		for _, c := range targets {
			h.remove(c)
		}
	}()
	buffer := make([]byte, 65535)
	for {
		n, a, e := packet.ReadFrom(buffer)
		if e != nil {
			return e
		}
		dst, e := netaddr.From(a)
		if e != nil {
			return e
		}
		target := targets[dst]
		if target == nil {
			if len(targets) >= 128 {
				return wire.ErrFrame
			}
			target, e = h.protected.DialContext(h.ctx, "udp", net.JoinHostPort(dst.Host, portString(dst.Port)))
			if e != nil {
				return e
			}
			if !h.addTarget(target) {
				return net.ErrClosed
			}
			targets[dst] = target
			readers.Add(1)
			go func(c net.Conn) {
				defer readers.Done()
				scratch := make([]byte, 65535)
				for {
					n, e := c.Read(scratch)
					if e != nil {
						return
					}
					if _, e = packet.WriteTo(scratch[:n], c.RemoteAddr()); e != nil {
						_ = packet.Close()
						return
					}
					traffic.CountDownload(n, h.total)
				}
			}(target)
		}
		nw, e := target.Write(buffer[:n])
		if e != nil {
			return e
		}
		if nw != n {
			return io.ErrShortWrite
		}
		traffic.CountUpload(n, h.total)
	}
}
