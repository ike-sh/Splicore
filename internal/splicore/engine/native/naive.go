package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/naive/backend"
	"net"
	"sync"
	"sync/atomic"
)

type NaiveCompiler struct{}

func (NaiveCompiler) ProtocolID() string { return "naive" }
func (NaiveCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c NaiveCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
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
		return nil, identity.Err(identity.Invalid, "invalid Naive TLS snapshot")
	}
	dialer, err := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &naiveHandle{ctx: ctx, cancel: cancel, endpoint: in.Inbound.Listeners[0].Endpoint, mode: settings.Mode, protected: dialer,
		total: &traffic.Counter{}, users: map[string]*traffic.Counter{}, done: make(chan struct{})}
	for index, binding := range in.Bindings {
		id := string(binding.ID)
		payload := in.Credentials[index].Payload.(access.UsernamePasswordPayload)
		h.users[id] = &traffic.Counter{}
		h.credentials = append(h.credentials, naiveCredential{id: id, username: sha256.Sum256([]byte(payload.Username.Reveal())), password: sha256.Sum256([]byte(payload.Password.Reveal()))})
	}
	connect, _ := module.Duration(settings.ConnectTimeout, "5s")
	idle, _ := module.Duration(settings.IdleTimeout, "10m")
	h.server, err = backend.NewServer(backend.ServerConfig{Mode: settings.Mode, TLS: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12},
		MaxStreams: settings.MaxStreams, ConnectTimeout: connect, IdleTimeout: idle, Authenticate: h.authenticate,
		Dial: func(ctx context.Context, id, authority string) (net.Conn, error) {
			if !h.admitted.Load() || h.users[id] == nil {
				return nil, net.ErrClosed
			}
			return h.protected.DialContext(ctx, "tcp", authority)
		},
		Relay: func(ctx context.Context, id string, client, target net.Conn) {
			counted := traffic.Conn(client, h.total, h.users[id])
			defer counted.Close()
			relay.Join(ctx, counted, target)
		}})
	if err != nil {
		cancel()
		return nil, err
	}
	return h, nil
}

type naiveCredential struct {
	id                 string
	username, password [32]byte
}
type naiveHandle struct {
	mu                sync.Mutex
	ctx               context.Context
	cancel            context.CancelFunc
	endpoint          access.Endpoint
	mode              string
	protected         *underlay.Dialer
	server            *backend.Server
	listener          net.Listener
	packet            net.PacketConn
	started, closed   bool
	running, admitted atomic.Bool
	done              chan struct{}
	total             *traffic.Counter
	users             map[string]*traffic.Counter
	credentials       []naiveCredential
}

func (h *naiveHandle) authenticate(username, password string) (string, bool) {
	if !h.admitted.Load() {
		return "", false
	}
	u, p := sha256.Sum256([]byte(username)), sha256.Sum256([]byte(password))
	id := ""
	for _, cred := range h.credentials {
		match := subtle.ConstantTimeCompare(u[:], cred.username[:]) & subtle.ConstantTimeCompare(p[:], cred.password[:])
		if match == 1 {
			id = cred.id
		}
	}
	return id, id != ""
}
func (h *naiveHandle) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || ctx.Err() != nil {
		return identity.Err(identity.Unavailable, "Naive runtime closed or canceled")
	}
	if h.started {
		return nil
	}
	address := net.JoinHostPort(h.endpoint.Host, portString(h.endpoint.Port))
	var err error
	if h.mode == "quic" {
		h.packet, err = (&net.ListenConfig{}).ListenPacket(ctx, "udp", address)
	} else {
		h.listener, err = (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	}
	if err != nil {
		if addressInUse(err) {
			return identity.Err(identity.PortConflict, "Naive listener port is already in use")
		}
		return identity.Err(identity.Unavailable, "Naive listener start failed")
	}
	h.started = true
	h.running.Store(true)
	go func() {
		defer close(h.done)
		defer h.running.Store(false)
		if h.mode == "quic" {
			_ = h.server.ServeUDP(h.packet)
		} else {
			_ = h.server.ServeTCP(h.listener)
		}
	}()
	return nil
}
func (h *naiveHandle) Activate() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.admitted.Store(true)
	}
}
func (h *naiveHandle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "Naive listener is not healthy")
	}
	return nil
}
func (h *naiveHandle) Stats() ports.Stats { return h.total.Snapshot() }
func (h *naiveHandle) BindingStats(id identity.ID) ports.Stats {
	if user := h.users[string(id)]; user != nil {
		return user.Snapshot()
	}
	return ports.Stats{}
}
func (h *naiveHandle) Close(ctx context.Context) error {
	h.mu.Lock()
	h.closed = true
	h.admitted.Store(false)
	h.running.Store(false)
	h.cancel()
	started := h.started
	listener, packet := h.listener, h.packet
	h.mu.Unlock()
	// HTTP/3 must send connection close while the owned UDP socket is still
	// open. Closing it first leaves peers using a stale connection on reload.
	err := h.server.Close(ctx)
	if listener != nil {
		_ = listener.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
	if err != nil {
		return identity.Err(identity.Unavailable, "Naive shutdown timed out")
	}
	if started {
		select {
		case <-h.done:
		case <-ctx.Done():
			return identity.Err(identity.Unavailable, "Naive shutdown timed out")
		}
	}
	return nil
}
