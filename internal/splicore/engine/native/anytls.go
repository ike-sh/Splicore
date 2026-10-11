package native

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/address"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/uot2"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/anytls/padding"
	"github.com/ike-sh/Splicore/protocol/anytls/session"
	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

type AnyTLSCompiler struct{}

func (AnyTLSCompiler) ProtocolID() string { return "anytls" }
func (AnyTLSCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c AnyTLSCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
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
		return nil, identity.Err(identity.Invalid, "invalid AnyTLS TLS snapshot")
	}
	protected, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	scheme, _ := padding.Parse(settings.PaddingScheme)
	h := &anytlsHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, protected: protected,
		tls:    &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: slices.Clone(settings.ALPN)},
		config: session.Config{Version: settings.Version, Padding: scheme, MaxStreams: settings.MaxStreams}, maxSessions: settings.MaxSessions,
		connections: map[net.Conn]bool{}, keys: map[wire.AuthKey]string{}, users: map[string]*traffic.Counter{}, total: &traffic.Counter{}, done: make(chan struct{})}
	for i, b := range in.Bindings {
		id := string(b.ID)
		h.users[id] = &traffic.Counter{}
		h.keys[wire.PasswordKey(in.Credentials[i].Payload.(access.PasswordPayload).Password.Reveal())] = id
	}
	return h, nil
}

type anytlsHandle struct {
	lifecycle, mu     sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	protected         *underlay.Dialer
	tls               *tls.Config
	listener          net.Listener
	config            session.Config
	maxSessions       int
	connections       map[net.Conn]bool
	keys              map[wire.AuthKey]string
	users             map[string]*traffic.Counter
	total             *traffic.Counter
	wg                sync.WaitGroup
	done              chan struct{}
	running, admitted atomic.Bool
	started, closed   bool
}

func (h *anytlsHandle) Start(ctx context.Context) error {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "AnyTLS runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port)))
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "TCP listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "AnyTLS listener start failed")
	}
	h.listener = l
	h.started = true
	h.running.Store(true)
	h.wg.Add(1)
	go h.accept()
	return nil
}
func (h *anytlsHandle) Activate() {
	h.lifecycle.Lock()
	defer h.lifecycle.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *anytlsHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "AnyTLS listener is not healthy")
	}
	return nil
}
func (h *anytlsHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *anytlsHandle) BindingStats(id identity.ID) ports.Stats {
	if c := h.users[string(id)]; c != nil {
		return c.Snapshot()
	}
	return ports.Stats{}
}
func (h *anytlsHandle) Close(ctx context.Context) error {
	h.lifecycle.Lock()
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		h.admitted.Store(false)
		h.running.Store(false)
		all := make([]net.Conn, 0, len(h.connections))
		for c := range h.connections {
			all = append(all, c)
		}
		h.mu.Unlock()
		h.cancel()
		if h.listener != nil {
			h.listener.Close()
		}
		for _, c := range all {
			c.Close()
		}
		go func() { h.wg.Wait(); clear(h.keys); close(h.done) }()
	} else {
		h.mu.Unlock()
	}
	h.lifecycle.Unlock()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "AnyTLS shutdown timed out")
	}
}
func (h *anytlsHandle) accept() {
	defer h.wg.Done()
	defer h.running.Store(false)
	for {
		raw, err := h.listener.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed || !h.admitted.Load() || len(h.connections) >= h.maxSessions {
			h.mu.Unlock()
			raw.Close()
			continue
		}
		h.connections[raw] = true
		h.wg.Add(1)
		h.mu.Unlock()
		go h.serve(raw)
	}
}
func (h *anytlsHandle) serve(raw net.Conn) {
	defer h.wg.Done()
	defer raw.Close()
	defer func() { h.mu.Lock(); delete(h.connections, raw); h.mu.Unlock() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	secure := tls.Server(raw, h.tls)
	if secure.HandshakeContext(h.ctx) != nil {
		return
	}
	key, err := wire.ReadAuthentication(secure)
	if err != nil {
		return
	}
	id, authenticated := wire.Match(key, h.keys)
	clear(key[:])
	if !authenticated || !h.admitted.Load() {
		return
	}
	_ = secure.SetWriteDeadline(time.Time{})
	s, err := session.NewServer(secure, h.config, func(stream *session.Stream) { h.proxy(stream, h.users[id]) })
	if err != nil {
		return
	}
	defer s.Close()
	s.Wait()
}
func (h *anytlsHandle) proxy(stream *session.Stream, user *traffic.Counter) {
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	dst, err := address.ReadSOCKS(stream)
	if err != nil {
		_ = stream.Accept(err)
		return
	}
	if dst.Host == uot2.MagicHost {
		// The v2 acknowledgement covers opening the reserved proxy target;
		// the UoT request follows it and is validated separately.
		if stream.Accept(nil) != nil {
			return
		}
		packet, err := uot2.Server(stream)
		if err != nil {
			return
		}
		defer packet.Close()
		_ = packet.SetDeadline(time.Time{})
		counted := traffic.Packet(packet, h.total, user)
		defer counted.Close()
		_ = relay.Packets(stream.Context(), counted, func(ctx context.Context, target access.Endpoint) (net.Conn, error) {
			return h.protected.DialContext(ctx, "udp", net.JoinHostPort(target.Host, portString(target.Port)))
		}, 30*time.Second)
		return
	}
	if dst.Validate() != nil {
		_ = stream.Accept(identity.Err(identity.Invalid, "invalid destination"))
		return
	}
	ctx, cancel := context.WithTimeout(stream.Context(), 5*time.Second)
	defer cancel()
	target, err := h.protected.DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, portString(dst.Port)))
	if stream.Accept(err) != nil || err != nil {
		if target != nil {
			target.Close()
		}
		return
	}
	defer target.Close()
	_ = stream.SetDeadline(time.Time{})
	counted := traffic.Conn(stream, h.total, user)
	defer counted.Close()
	relay.Join(stream.Context(), counted, target)
}

func anytlsAlert(size int) { slog.Warn("AnyTLS peer alert closed the session", "payload_size", size) }
