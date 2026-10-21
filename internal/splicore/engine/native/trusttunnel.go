package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
)

type TrustTunnelCompiler struct{}

func (TrustTunnelCompiler) ProtocolID() string { return "trusttunnel" }
func (TrustTunnelCompiler) Supports(in ports.RuntimeIntent) error {
	_, e := (module.Module{}).BuildRuntime(context.Background(), in)
	return e
}
func (c TrustTunnelCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if e := c.Supports(in); e != nil {
		return nil, e
	}
	settings, _ := module.Decode(in.Inbound.Settings.Data)
	cert, key, e := tlsSnapshot(settings.TLS)
	if e != nil {
		return nil, e
	}
	defer clear(key)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return nil, identity.Err(identity.Invalid, "invalid TrustTunnel TLS snapshot")
	}
	protected, e := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if e != nil {
		return nil, e
	}
	h := &trustTunnelHandle{endpoint: in.Inbound.Listeners[0].Endpoint, mode: settings.Mode, protected: protected, total: &traffic.Counter{}, users: map[string]*traffic.Counter{}}
	for i, b := range in.Bindings {
		id := string(b.ID)
		p := in.Credentials[i].Payload.(access.UsernamePasswordPayload)
		h.users[id] = &traffic.Counter{}
		h.credentials = append(h.credentials, trustTunnelCredential{id, sha256.Sum256([]byte(p.Username.Reveal())), sha256.Sum256([]byte(p.Password.Reveal()))})
	}
	connect, _ := module.Duration(settings.ConnectTimeout, "30s")
	idle, _ := module.Duration(settings.IdleTimeout, "10m")
	udpIdle, _ := module.Duration(settings.UDPIdleTimeout, "120s")
	cfg := session.ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, HTTP2: settings.Mode != "http3", HTTP3: settings.Mode != "http2", MaxStreams: settings.MaxStreams, MaxSessions: settings.MaxSessions, MaxFlows: settings.MaxFlows, ConnectTimeout: connect, IdleTimeout: idle, UDPIdleTimeout: udpIdle, Authenticate: h.authenticate, DialTCP: func(ctx context.Context, id, a string) (net.Conn, error) {
		if !h.admitted.Load() || h.users[id] == nil {
			return nil, net.ErrClosed
		}
		return h.protected.DialContext(ctx, "tcp", a)
	}, DialUDP: func(ctx context.Context, id, a string) (net.Conn, error) {
		if !h.admitted.Load() || h.users[id] == nil {
			return nil, net.ErrClosed
		}
		n, e := h.protected.DialContext(ctx, "udp", a)
		if e != nil {
			return nil, e
		}
		return &trustTunnelTargetUDP{Conn: n, total: h.total, user: h.users[id], release: traffic.Open(false, h.total, h.users[id])}, nil
	}, Relay: func(ctx context.Context, id string, a, b net.Conn) {
		counted := traffic.Conn(a, h.total, h.users[id])
		defer counted.Close()
		relay.Join(ctx, counted, b)
	}}
	if settings.ICMP {
		cfg.Echo = trustTunnelEcho(protected)
	}
	h.server, e = session.NewServer(cfg)
	if e != nil {
		return nil, e
	}
	return h, nil
}

type trustTunnelCredential struct {
	id                 string
	username, password [32]byte
}
type trustTunnelHandle struct {
	mu              sync.Mutex
	endpoint        access.Endpoint
	mode            string
	protected       *underlay.Dialer
	server          *session.Server
	listener        net.Listener
	packet          net.PacketConn
	started, closed bool
	admitted        atomic.Bool
	running         atomic.Int32
	workers         sync.WaitGroup
	total           *traffic.Counter
	users           map[string]*traffic.Counter
	credentials     []trustTunnelCredential
}

func (h *trustTunnelHandle) authenticate(u, p string) (string, bool) {
	if !h.admitted.Load() {
		return "", false
	}
	username, password := sha256.Sum256([]byte(u)), sha256.Sum256([]byte(p))
	id := ""
	for _, c := range h.credentials {
		if subtle.ConstantTimeCompare(username[:], c.username[:])&subtle.ConstantTimeCompare(password[:], c.password[:]) == 1 {
			id = c.id
		}
	}
	return id, id != ""
}
func (h *trustTunnelHandle) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "TrustTunnel runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	address := module.Address(h.endpoint)
	var e error
	if h.mode != "http3" {
		h.listener, e = (&net.ListenConfig{}).Listen(ctx, "tcp", address)
		if e != nil {
			return trustTunnelBindError(e)
		}
	}
	if h.mode != "http2" {
		h.packet, e = (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
		if e != nil {
			if h.listener != nil {
				_ = h.listener.Close()
			}
			return trustTunnelBindError(e)
		}
	}
	h.started = true
	if h.listener != nil {
		h.running.Add(1)
		h.workers.Add(1)
		go func() { defer h.workers.Done(); defer h.running.Add(-1); _ = h.server.ServeTCP(h.listener) }()
	}
	if h.packet != nil {
		h.running.Add(1)
		h.workers.Add(1)
		go func() { defer h.workers.Done(); defer h.running.Add(-1); _ = h.server.ServeUDP(h.packet) }()
	}
	return nil
}
func trustTunnelBindError(e error) error {
	if addressInUse(e) {
		return identity.Err(identity.PortConflict, "TrustTunnel listener port is already in use")
	}
	return identity.Err(identity.Unavailable, "TrustTunnel listener start failed")
}
func (h *trustTunnelHandle) Activate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *trustTunnelHandle) Health(ctx context.Context) error {
	h.mu.Lock()
	expected := int32(1)
	if h.mode == "auto" {
		expected = 2
	}
	closed := h.closed
	h.mu.Unlock()
	if closed || ctx.Err() != nil || h.running.Load() != expected {
		return identity.Err(identity.Unavailable, "TrustTunnel listener is not healthy")
	}
	return nil
}
func (h *trustTunnelHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *trustTunnelHandle) BindingStats(id identity.ID) ports.Stats {
	if u := h.users[string(id)]; u != nil {
		return u.Snapshot()
	}
	return ports.Stats{}
}
func (h *trustTunnelHandle) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	h.admitted.Store(false)
	listener, packet := h.listener, h.packet
	h.mu.Unlock()
	e := h.server.Close(ctx)
	if listener != nil {
		_ = listener.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
	if e != nil {
		return identity.Err(identity.Unavailable, "TrustTunnel shutdown timed out")
	}
	done := make(chan struct{})
	go func() { h.workers.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return identity.Err(identity.Unavailable, "TrustTunnel shutdown timed out")
	}
}

type trustTunnelTargetUDP struct {
	net.Conn
	total, user *traffic.Counter
	release     func()
	once        sync.Once
}

func (c *trustTunnelTargetUDP) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	traffic.CountDownload(n, c.total, c.user)
	return n, e
}
func (c *trustTunnelTargetUDP) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	traffic.CountUpload(n, c.total, c.user)
	return n, e
}
func (c *trustTunnelTargetUDP) Close() error { c.once.Do(c.release); return c.Conn.Close() }
