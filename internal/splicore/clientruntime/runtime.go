// Package clientruntime owns local sockets, sessions and immutable routing generations.
package clientruntime

import (
	"bufio"
	"context"
	"errors"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type counter struct {
	upload, download, total, active             atomic.Int64
	udpTotal, udpActive, packetsUp, packetsDown atomic.Int64
}
type passiveHealth struct {
	available bool
	lastError string
	at        time.Time
}

var succeededHealth = &passiveHealth{available: true}
var failedHealth = &passiveHealth{lastError: "outbound_connection_failed"}

func (c *counter) stats() TrafficStats {
	return TrafficStats{Stats: ports.Stats{Upload: c.upload.Load(), Download: c.download.Load(), Sessions: c.total.Load(), Active: c.active.Load()}, UDPAssociations: c.udpTotal.Load(), UDPActive: c.udpActive.Load(), PacketsUpload: c.packetsUp.Load(), PacketsDownload: c.packetsDown.Load()}
}

type snapshot struct {
	onReleased                            func()
	network                               *networkruntime.Engine
	state                                 client.ProfileState
	outbounds                             map[identity.ID]ports.ClientDialer
	routes                                map[identity.ID]identity.ID
	refs                                  atomic.Int64
	inCounters, outCounters, nodeCounters map[identity.ID]*counter
}

func (s *snapshot) release() {
	if s.refs.Add(-1) == 0 {
		if s.network != nil {
			s.network.Close()
		}
		for _, o := range s.outbounds {
			if o != nil {
				_ = o.Close()
			}
		}
		if s.onReleased != nil {
			s.onReleased()
		}
	}
}

type localListener struct {
	spec   client.LocalInbound
	socket net.Listener
	ready  atomic.Bool
	done   chan struct{}
}
type session struct {
	id                      identity.ID
	inbound, outbound, node identity.ID
	local                   net.Conn
	remote                  net.Conn       // assigned only while holding Manager.mu
	packet                  net.PacketConn // assigned only while holding Manager.mu
	kind                    string
	dialer                  ports.ClientDialer
	cancel                  context.CancelFunc
	stats                   counter
}
type Manager struct {
	// routeMu protects acquiring a generation reference versus retirement, never payload I/O.
	routeMu                      sync.RWMutex
	current                      atomic.Pointer[snapshot]
	mu                           sync.Mutex
	listeners                    map[identity.ID]*localListener
	networkOwners                map[*networkruntime.Engine]bool
	sessions                     map[identity.ID]*session
	inStats, outStats, nodeStats map[identity.ID]*counter
	wg                           sync.WaitGroup
	closed                       bool
	changed                      chan struct{}
	udpIdle                      time.Duration
}

func New() *Manager {
	return &Manager{listeners: map[identity.ID]*localListener{}, networkOwners: map[*networkruntime.Engine]bool{}, sessions: map[identity.ID]*session{}, inStats: map[identity.ID]*counter{}, outStats: map[identity.ID]*counter{}, nodeStats: map[identity.ID]*counter{}, changed: make(chan struct{}), udpIdle: 2 * time.Minute}
}

type Prepared struct {
	m               *Manager
	s               *snapshot
	listeners       map[identity.ID]*localListener
	newListeners    []*localListener
	used            bool
	restartSessions bool
}

// RestartSessions rebuilds outbound generations and terminates existing sessions
// after commit; unchanged healthy listeners can retain their bound sockets.
func (p *Prepared) RestartSessions() { p.restartSessions = true }

func Validate(state client.ProfileState, credentials map[identity.ID]access.Credential, registry *registry.Outbounds) error {
	if err := state.Validate(); err != nil {
		return err
	}
	nodes := map[identity.ID]client.RemoteNode{}
	for _, n := range state.Nodes {
		nodes[n.ID] = n
		// All nodes require a supported client protocol, even before an outbound references them.
		supported := false
		for _, cap := range registry.Capabilities() {
			if cap.Protocol == n.Protocol.Protocol {
				f, _ := registry.Get(cap.Protocol, cap.Engine)
				if err := f.Validate(n, credentials[n.CredentialID]); err != nil {
					return err
				}
				supported = true
				break
			}
		}
		if !supported {
			return identity.Err(identity.UnsupportedEngineForProtocol, "client protocol is unavailable")
		}
	}
	for _, o := range state.Outbounds {
		if o.Kind == "direct" {
			continue
		}
		f, err := registry.Get(nodes[*o.NodeID].Protocol.Protocol, o.Engine)
		if err != nil {
			return err
		}
		n := nodes[*o.NodeID]
		if err = f.Validate(n, credentials[n.CredentialID]); err != nil {
			return err
		}
	}
	return nil
}
func (m *Manager) Prepare(ctx context.Context, state client.ProfileState, credentials map[identity.ID]access.Credential, registry *registry.Outbounds) (p *Prepared, err error) {
	return m.PrepareWithRestart(ctx, state, credentials, registry, false)
}
func (m *Manager) PrepareWithRestart(ctx context.Context, state client.ProfileState, credentials map[identity.ID]access.Credential, registry *registry.Outbounds, restart bool) (p *Prepared, err error) {
	if err = Validate(state, credentials, registry); err != nil {
		return nil, err
	}
	s := &snapshot{state: state.Clone(), outbounds: map[identity.ID]ports.ClientDialer{}, routes: map[identity.ID]identity.ID{}}
	s.refs.Store(1)
	p = &Prepared{m: m, s: s, listeners: map[identity.ID]*localListener{}}
	p.restartSessions = restart
	defer func() {
		if err != nil {
			p.Abort()
		}
	}()
	localIDs := make([]identity.ID, 0, len(state.LocalInbounds))
	declared := map[identity.ID]ports.ClientDialer{}
	for _, o := range state.Outbounds {
		declared[o.ID] = nil
	}
	for _, i := range state.LocalInbounds {
		localIDs = append(localIDs, i.ID)
	}
	bootstrap, err := networkruntime.New(state.Network, declared, nil, localIDs...)
	if err != nil {
		return p, err
	}
	defer bootstrap.Close()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return p, identity.Err(identity.Unavailable, "client runtime closed")
	}
	if !state.Enabled {
		s.network, err = networkruntime.New(state.Network, declared, func(id identity.ID) networkruntime.Passive {
			lease, ok := s.outbounds[id].(*dialerLease)
			if !ok {
				return networkruntime.Passive{State: "unknown"}
			}
			h := lease.health.Load()
			if h == nil {
				return networkruntime.Passive{State: "unknown"}
			}
			if h.available {
				return networkruntime.Passive{State: "healthy", At: h.at}
			}
			return networkruntime.Passive{State: "unhealthy", At: h.at}
		}, localIDs...)
		if err != nil {
			return p, err
		}

		return p, err
	}
	nodes := map[identity.ID]client.RemoteNode{}
	for _, n := range state.Nodes {
		nodes[n.ID] = n
	}
	oldGeneration := m.acquire()
	if oldGeneration != nil {
		defer oldGeneration.release()
	}
	for _, o := range state.Outbounds {
		var n client.RemoteNode
		if o.NodeID != nil {
			n = nodes[*o.NodeID]
		}
		key := effectiveKey(o, n)
		key += bootstrapKey(state.Network, n)
		if !restart && oldGeneration != nil {
			if lease, ok := oldGeneration.outbounds[o.ID].(*dialerLease); ok && lease.key == key {
				lease.refs.Add(1)
				s.outbounds[o.ID] = lease
				continue
			}
		}
		var d ports.ClientDialer
		if o.Kind == "direct" {
			d = directDialer{}
		} else {
			n := nodes[*o.NodeID]
			if state.Network.DNS.Enabled && net.ParseIP(n.Endpoint.Host) == nil {
				addresses, resolveErr := bootstrap.Bootstrap(ctx, n.Endpoint.Host)
				if resolveErr != nil || len(addresses) == 0 {
					return p, identity.Err(identity.Unavailable, "remote node bootstrap resolution failed")
				}
				n.Endpoint.Host = addresses[0].String()
			}
			f, _ := registry.Get(n.Protocol.Protocol, o.Engine)
			d, err = f.Build(ctx, n, credentials[n.CredentialID])
			if err != nil {
				return p, err
			}
		}
		lease := &dialerLease{dialer: d, key: key}
		lease.refs.Store(1)
		s.outbounds[o.ID] = lease
	}
	s.network, err = networkruntime.New(state.Network, s.outbounds, func(id identity.ID) networkruntime.Passive {
		lease, ok := s.outbounds[id].(*dialerLease)
		if !ok {
			return networkruntime.Passive{State: "unknown"}
		}
		h := lease.health.Load()
		if h == nil {
			return networkruntime.Passive{State: "unknown"}
		}
		if h.available {
			return networkruntime.Passive{State: "healthy", At: h.at}
		}
		return networkruntime.Passive{State: "unhealthy", At: h.at}
	}, localIDs...)
	if err != nil {
		return p, err
	}

	if oldGeneration != nil {
		s.network.Inherit(oldGeneration.network)
	}
	for _, i := range state.LocalInbounds {
		selected := i.SelectedOutbound
		if selected == "" {
			selected = state.Route.DefaultOutbound
		}
		s.routes[i.ID] = selected
		m.mu.Lock()
		old := m.listeners[i.ID]
		m.mu.Unlock()
		if old != nil && old.ready.Load() && old.spec.Listen == i.Listen {
			p.listeners[i.ID] = old
			continue
		}
		var l net.Listener
		l, err = (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(i.Listen.Host, strconv.Itoa(int(i.Listen.Port))))
		if err != nil {
			var op *net.OpError
			if errors.As(err, &op) && op.Op == "listen" {
				return p, identity.Err(identity.PortConflict, "local listener cannot bind")
			}
			return p, identity.Err(identity.Unavailable, "local listener start failed")
		}
		h := &localListener{spec: i, socket: l, done: make(chan struct{})}
		p.listeners[i.ID] = h
		p.newListeners = append(p.newListeners, h)
	}
	if ctx.Err() != nil {
		return p, identity.Err(identity.Unavailable, "client start canceled")
	}
	return p, nil
}
func (p *Prepared) Abort() {
	if p == nil || p.used {
		return
	}
	p.used = true
	for _, l := range p.newListeners {
		_ = l.socket.Close()
	}
	p.s.release()
}

// Activate is called only after SQLite commit. Existing sessions own their old generation.
func (p *Prepared) Activate() {
	if p.used {
		return
	}
	p.used = true
	m := p.m
	m.mu.Lock()
	m.networkOwners[p.s.network] = true
	p.s.onReleased = func() { m.mu.Lock(); delete(m.networkOwners, p.s.network); m.mu.Unlock() }
	removed := []*localListener{}
	for id, l := range m.listeners {
		if p.listeners[id] != l {
			l.ready.Store(false)
			removed = append(removed, l)
		}
	}
	m.listeners = p.listeners
	ensure := func(table map[identity.ID]*counter, id identity.ID) {
		if table[id] == nil {
			table[id] = &counter{}
		}
	}
	for _, i := range p.s.state.LocalInbounds {
		ensure(m.inStats, i.ID)
	}
	for _, o := range p.s.state.Outbounds {
		ensure(m.outStats, o.ID)
	}
	for _, n := range p.s.state.Nodes {
		ensure(m.nodeStats, n.ID)
	}
	p.s.inCounters = map[identity.ID]*counter{}
	p.s.outCounters = map[identity.ID]*counter{}
	p.s.nodeCounters = map[identity.ID]*counter{}
	for _, i := range p.s.state.LocalInbounds {
		p.s.inCounters[i.ID] = m.inStats[i.ID]
	}
	for _, o := range p.s.state.Outbounds {
		p.s.outCounters[o.ID] = m.outStats[o.ID]
	}
	for _, n := range p.s.state.Nodes {
		p.s.nodeCounters[n.ID] = m.nodeStats[n.ID]
	}
	// Retired sessions retain their counter pointers; deleted resources do not accumulate in the manager.
	for id := range m.inStats {
		if p.s.inCounters[id] == nil {
			delete(m.inStats, id)
		}
	}
	for id := range m.outStats {
		if p.s.outCounters[id] == nil {
			delete(m.outStats, id)
		}
	}
	for id := range m.nodeStats {
		if p.s.nodeCounters[id] == nil {
			delete(m.nodeStats, id)
		}
	}
	m.routeMu.Lock()
	old := m.current.Swap(p.s)
	m.routeMu.Unlock()
	for _, l := range p.newListeners {
		m.wg.Add(1)
		l.ready.Store(true)
		go m.accept(l)
	}
	closing := []*session{}
	for _, s := range m.sessions {
		if p.restartSessions {
			closing = append(closing, s)
			continue
		}
		for _, l := range removed {
			if s.inbound == l.spec.ID {
				closing = append(closing, s)
				break
			}
		}
	}
	m.mu.Unlock()
	if p.s.state.Enabled {
		p.s.network.Start()
	}
	for _, l := range removed {
		_ = l.socket.Close()
	}
	for _, s := range closing {
		m.closeSession(s)
	}
	if old != nil {
		if !p.s.state.Enabled || p.restartSessions {
			old.network.Close()
		} else {
			old.network.StopScheduler()
		}
		old.release()
	}
}
func (m *Manager) acquire() *snapshot {
	m.routeMu.RLock()
	s := m.current.Load()
	if s != nil {
		s.refs.Add(1)
	}
	m.routeMu.RUnlock()
	return s
}
func (m *Manager) accept(l *localListener) {
	defer m.wg.Done()
	defer close(l.done)
	for {
		c, err := l.socket.Accept()
		if err != nil {
			l.ready.Store(false)
			return
		}
		m.mu.Lock()
		if m.closed || !l.ready.Load() || len(m.sessions) >= 4096 {
			m.mu.Unlock()
			_ = c.Close()
			continue
		}
		id, err := identity.NewID()
		if err != nil {
			m.mu.Unlock()
			_ = c.Close()
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		s := &session{id: id, inbound: l.spec.ID, local: c, cancel: cancel}
		m.sessions[id] = s
		m.wg.Add(1)
		m.mu.Unlock()
		go m.serve(ctx, s)
	}
}
func (m *Manager) closeSession(s *session) {
	s.cancel()
	_ = s.local.Close()
	m.mu.Lock()
	remote := s.remote
	packet := s.packet
	m.mu.Unlock()
	if remote != nil {
		_ = remote.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
}
func (m *Manager) serve(ctx context.Context, s *session) {
	defer m.wg.Done()
	var gen *snapshot
	defer func() {
		m.closeSession(s)
		// Conn.Close may return pooled resources to its adapter. Keep the generation
		// alive until that connection cleanup is finished, including retired adapters.
		if gen != nil {
			gen.release()
		}
		m.mu.Lock()
		delete(m.sessions, s.id)
		close(m.changed)
		m.changed = make(chan struct{})
		m.mu.Unlock()
	}()
	_ = s.local.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(s.local)
	auth, err := socks5.ReadAuthRequest(reader)
	if err != nil {
		return
	}
	accepted := false
	for _, method := range auth.Methods {
		if method == socks5.AuthTypeNotRequired {
			accepted = true
		}
	}
	method := socks5.AuthTypeNoAcceptedMethods
	if accepted {
		method = socks5.AuthTypeNotRequired
	}
	if socks5.WriteAuthResponse(s.local, socks5.AuthResponse{Method: method}) != nil || !accepted {
		return
	}
	req, err := socks5.ReadRequest(reader)
	if err != nil {
		return
	}
	reply := func(code byte) {
		_ = socks5.WriteResponse(s.local, socks5.Response{ReplyCode: code, Bind: M.SocksaddrFromNet(s.local.LocalAddr())})
	}
	if req.Command != socks5.CommandConnect && req.Command != socks5.CommandUDPAssociate {
		reply(socks5.ReplyCodeUnsupported)
		return
	}
	target := access.Endpoint{Host: req.Destination.AddrString(), Port: req.Destination.Port}
	if req.Command == socks5.CommandConnect && target.Validate() != nil {
		reply(socks5.ReplyCodeAddressTypeUnsupported)
		return
	}
	gen = m.acquire()
	if gen == nil {
		reply(socks5.ReplyCodeFailure)
		return
	}
	oid, ok := gen.routes[s.inbound]
	if !ok || gen.outbounds[oid] == nil {
		reply(socks5.ReplyCodeFailure)
		return
	}
	if req.Command == socks5.CommandUDPAssociate {
		m.mu.Lock()
		s.kind = "udp_association"
		m.mu.Unlock()
		m.serveUDP(ctx, s, reader, req.Destination, gen)
		return
	}
	selected, resolved, routeErr := selectRoute(ctx, gen, s.inbound, target, "tcp", nil)
	if routeErr != nil {
		reply(socks5.ReplyCodeFailure)
		return
	}
	if selected.Selected.Kind == P.Reject {
		reply(socks5.ReplyCodeNotAllowed)
		return
	}
	oid = selectedOutbound(selected.Selected)
	target = resolved
	var node identity.ID
	for _, o := range gen.state.Outbounds {
		if o.ID == oid && o.NodeID != nil {
			node = *o.NodeID
		}
	}
	m.mu.Lock()
	s.outbound = oid
	s.node = node
	s.dialer = gen.outbounds[oid]
	s.kind = "tcp"
	if req.Command == socks5.CommandUDPAssociate {
		s.kind = "udp_association"
	}
	oc := gen.outCounters[oid]
	ic := gen.inCounters[s.inbound]
	nc := gen.nodeCounters[node]
	m.mu.Unlock()
	adapter := gen.outbounds[oid].(*dialerLease)
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	remote, err := gen.outbounds[oid].DialContext(dialCtx, target)
	cancel()
	if err != nil {
		adapter.failed()
		reply(socks5.ReplyCodeForError(err))
		return
	}
	m.mu.Lock()
	s.remote = remote
	closed := m.closed || ctx.Err() != nil
	m.mu.Unlock()
	if closed {
		_ = remote.Close()
		return
	}
	for _, c := range []*counter{&s.stats, ic, oc, nc} {
		if c != nil {
			c.total.Add(1)
			c.active.Add(1)
		}
	}
	defer func() {
		for _, c := range []*counter{&s.stats, ic, oc, nc} {
			if c != nil {
				c.active.Add(-1)
			}
		}
	}()
	if err = socks5.WriteResponse(s.local, socks5.Response{ReplyCode: socks5.ReplyCodeSuccess, Bind: M.SocksaddrFromNet(s.local.LocalAddr())}); err != nil {
		return
	}
	_ = s.local.SetDeadline(time.Time{})
	counters := []*counter{&s.stats, ic, oc, nc}
	done := make(chan error, 2)
	copyStream := func(dst net.Conn, src io.Reader, upload bool) {
		_, e := io.Copy(&countWriter{writer: dst, counters: counters, upload: upload, onRead: adapter.success}, src)
		if e == nil {
			if h, ok := dst.(interface{ CloseWrite() error }); ok {
				e = h.CloseWrite()
			} else {
				_ = dst.Close()
			}
		}
		done <- e
	}
	go copyStream(remote, reader, true)
	go copyStream(s.local, remote, false)
	first := <-done
	if first != nil {
		if ctx.Err() == nil && s.stats.download.Load() == 0 {
			adapter.failed()
		}
		m.closeSession(s)
	}
	second := <-done
	if second != nil && ctx.Err() == nil && s.stats.download.Load() == 0 {
		adapter.failed()
	}
	if ctx.Err() == nil && s.stats.download.Load() == 0 {
		adapter.failed()
	}
}

type countWriter struct {
	writer   io.Writer
	counters []*counter
	upload   bool
	onRead   func()
}

func (w *countWriter) Write(b []byte) (int, error) {
	n, err := w.writer.Write(b)
	for _, c := range w.counters {
		if c != nil {
			if w.upload {
				c.upload.Add(int64(n))
			} else {
				c.download.Add(int64(n))
			}
		}
	}
	if n > 0 && !w.upload {
		w.onRead()
	}
	return n, err
}

type directDialer struct{}

func (directDialer) DialContext(ctx context.Context, e access.Endpoint) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port))))
}
func (directDialer) Close() error { return nil }
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		for _, l := range m.listeners {
			l.ready.Store(false)
			_ = l.socket.Close()
		}
	}
	sessions := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	owners := make([]*networkruntime.Engine, 0, len(m.networkOwners))
	for owner := range m.networkOwners {
		owners = append(owners, owner)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		m.closeSession(s)
	}
	// Also cancel control queries retaining a retired generation after a route update.
	for _, owner := range owners {
		owner.Close()
	}
	m.routeMu.Lock()
	old := m.current.Swap(nil)
	m.routeMu.Unlock()
	if old != nil {
		old.network.StopScheduler()
		old.release()
	}
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "client shutdown timed out")
	}
}
