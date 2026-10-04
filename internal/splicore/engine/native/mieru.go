package native

import (
	"context"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/underlay"
	"io"
	"net"
	"sync"
	"sync/atomic"

	ac "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	server "github.com/enfein/mieru/v3/apis/server"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"google.golang.org/protobuf/proto"
)

type MieruCompiler struct{}

func (MieruCompiler) ProtocolID() string { return "mieru" }
func (MieruCompiler) Supports(in ports.RuntimeIntent) error {
	_, e := (module.Module{}).BuildRuntime(context.Background(), in)
	return e
}
func (c MieruCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if e := c.Supports(in); e != nil {
		return nil, e
	}
	protected, e := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if e != nil {
		return nil, e
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &mieruHandle{protected: protected, ctx: runtimeCtx, cancel: cancel, server: server.NewServer(), total: &meter{}, users: map[string]*meter{}, closers: map[io.Closer]bool{}, done: make(chan struct{})}
	protocol := pb.TransportProtocol_TCP
	if s.Transport == "udp" {
		protocol = pb.TransportProtocol_UDP
	}
	endpoint := in.Inbound.Listeners[0].Endpoint
	config := &pb.ServerConfig{ListenIPAddress: proto.String(endpoint.Host), PortBindings: []*pb.PortBinding{{Port: proto.Int32(int32(endpoint.Port)), Protocol: protocol.Enum()}}, Mtu: proto.Int32(int32(s.MTU))}
	for n, b := range in.Bindings {
		p := in.Credentials[n].Payload.(access.UsernamePasswordPayload)
		name := p.Username.Reveal()
		h.users[name] = &meter{}
		h.bindings = append(h.bindings, mieruBinding{b.ID, h.users[name]})
		config.Users = append(config.Users, &pb.User{Name: proto.String(name), Password: proto.String(p.Password.Reveal())})
	}
	// Store only before Start. The protobuf snapshot is private and never mutated.
	if e := h.server.Store(&server.ServerConfig{Config: config, StreamListenerFactory: h, PacketListenerFactory: h}); e != nil {
		cancel()
		return nil, identity.Err(identity.Unavailable, "Mieru runtime construction failed")
	}
	return h, nil
}

type mieruBinding struct {
	id identity.ID
	m  *meter
}
type mieruHandle struct {
	protected         *underlay.Dialer
	lifecycle         sync.Mutex
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	server            server.Server
	total             *meter
	users             map[string]*meter
	bindings          []mieruBinding
	closers           map[io.Closer]bool
	workers           sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
	listenerConflict  atomic.Bool
}

func (*mieruHandle) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("MieruRuntime{[REDACTED]}")) }

func (h *mieruHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	h.mu.Lock()
	closed := h.closed
	h.mu.Unlock()
	if closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "Mieru runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	if e := h.server.Start(); e != nil {
		if h.listenerConflict.Load() {
			return identity.Err(identity.PortConflict, "Mieru listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "Mieru runtime start failed")
	}
	h.started = true
	h.running.Store(true)
	h.workers.Add(1)
	go h.accept()
	return nil
}
func (h *mieruHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() || !h.server.IsRunning() {
		return identity.Err(identity.Unavailable, "Mieru listener is not healthy")
	}
	return nil
}
func (h *mieruHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *mieruHandle) Stats() ports.Stats { return h.total.snapshot() }
func (h *mieruHandle) BindingStats(id identity.ID) ports.Stats {
	for _, b := range h.bindings {
		if b.id == id {
			return b.m.snapshot()
		}
	}
	return ports.Stats{}
}
func (h *mieruHandle) track(c io.Closer) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return false
	}
	h.closers[c] = true
	return true
}
func (h *mieruHandle) untrack(c io.Closer) { h.mu.Lock(); delete(h.closers, c); h.mu.Unlock() }
func (h *mieruHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	first := !h.closed
	h.closed = true
	h.mu.Unlock()
	if first {
		h.admitted.Store(false)
		h.running.Store(false)
		h.cancel()
		go func() {
			h.mu.Lock()
			all := make([]io.Closer, 0, len(h.closers))
			for c := range h.closers {
				all = append(all, c)
			}
			h.mu.Unlock()
			for _, c := range all {
				_ = c.Close()
			}
			_ = h.server.Stop()
			h.workers.Wait()
			close(h.done)
		}()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "Mieru shutdown timed out")
	}
}
func (h *mieruHandle) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, e := (&net.ListenConfig{}).Listen(ctx, network, address)
	if e != nil {
		h.listenerConflict.Store(addressInUse(e))
		return nil, e
	}
	if !h.track(l) {
		l.Close()
		return nil, net.ErrClosed
	}
	return &mieruListener{Listener: l, h: h}, nil
}
func (h *mieruHandle) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	p, e := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	if e != nil {
		h.listenerConflict.Store(addressInUse(e))
		return nil, e
	}
	if !h.track(p) {
		p.Close()
		return nil, net.ErrClosed
	}
	return &mieruAdmissionPacket{PacketConn: p, h: h}, nil
}

type mieruListener struct {
	net.Listener
	h *mieruHandle
}

func (l *mieruListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			l.h.running.Store(false)
			return nil, e
		}
		if !l.h.admitted.Load() {
			c.Close()
			continue
		}
		owned := &mieruRawConn{Conn: c, h: l.h}
		if !l.h.track(owned) {
			c.Close()
			return nil, net.ErrClosed
		}
		return owned, nil
	}
}

type mieruRawConn struct {
	net.Conn
	h    *mieruHandle
	once sync.Once
}

func (c *mieruRawConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.h.untrack(c) })
	return e
}

type mieruAdmissionPacket struct {
	net.PacketConn
	h *mieruHandle
}

func (p *mieruAdmissionPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, a, e := p.PacketConn.ReadFrom(b)
		if e != nil {
			p.h.running.Store(false)
			return n, a, e
		}
		if p.h.admitted.Load() {
			return n, a, nil
		}
	}
}
func (h *mieruHandle) accept() {
	defer h.workers.Done()
	defer h.running.Store(false)
	for {
		c, r, e := h.server.Accept()
		if e != nil {
			if h.ctx.Err() != nil || !h.server.IsRunning() {
				return
			}
			continue
		}
		user, ok := c.(ac.UserContext)
		if !ok || !h.admitted.Load() || h.users[user.UserName()] == nil {
			c.Close()
			continue
		}
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			c.Close()
			return
		}
		h.closers[c] = true
		h.workers.Add(1)
		h.mu.Unlock()
		go func() {
			defer h.workers.Done()
			defer h.untrack(c)
			defer c.Close()
			h.route(c, r, h.users[user.UserName()])
		}()
	}
}
func (h *mieruHandle) route(c net.Conn, r *model.Request, m *meter) {
	dst, e := r.ToNetAddrSpec()
	if e != nil {
		return
	}
	if dst.Net == "tcp" {
		remote, e := h.protected.DialContext(h.ctx, "tcp", dst.String())
		if e != nil {
			_ = model.WriteSocks5Response(c, 5, model.AddrSpec{IP: net.IPv4zero})
			return
		}
		defer remote.Close()
		if !h.track(remote) {
			return
		}
		defer h.untrack(remote)
		if e = model.WriteSocks5Response(c, 0, model.AddrSpec{IP: net.IPv4zero}); e != nil {
			return
		}
		counted := meteredConn(c, h.total, m)
		defer counted.Close()
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			_, err := io.Copy(remote, counted)
			if err == nil {
				// An upload EOF must leave the destination response readable.
				// DialContext returns TCPConn, whose half-close preserves Read.
				if tcp, ok := remote.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
					return
				}
			}
			remote.Close()
			counted.Close()
		}()
		_, _ = io.Copy(counted, remote)
		remote.Close()
		counted.Close()
		<-joined
		return
	}
	packet, e := h.protected.ListenPacket(h.ctx, "udp", ":0", "")
	if e != nil {
		return
	}
	defer packet.Close()
	if !h.track(packet) {
		return
	}
	defer h.untrack(packet)
	if e = model.WriteSocks5Response(c, 0, model.AddrSpec{IP: net.IPv4zero}); e != nil {
		return
	}
	_, _ = meterArrays([]*meter{h.total, m})
	defer func() { h.total.active.Add(-1); m.active.Add(-1) }()
	// Official wrappers own all UDP framing. Count payload after stripping them.
	tunnel := ac.NewUDPAssociateWrapper(ac.NewPacketOverStreamTunnel(c))
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		defer packet.Close()
		defer c.Close()
		b := make([]byte, 65535)
		for {
			n, a, e := tunnel.ReadFrom(b)
			if e != nil {
				return
			}
			written, e := packet.WriteTo(b[:n], a)
			h.total.upload.Add(int64(written))
			m.upload.Add(int64(written))
			if e != nil {
				return
			}
		}
	}()
	b := make([]byte, 65535)
	for {
		n, a, e := packet.ReadFrom(b)
		if e != nil {
			break
		}
		written, e := tunnel.WriteTo(b[:n], a)
		h.total.download.Add(int64(written))
		m.download.Add(int64(written))
		if e != nil {
			break
		}
	}
	packet.Close()
	c.Close()
	<-joined
}
