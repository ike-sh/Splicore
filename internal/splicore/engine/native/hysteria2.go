package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
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
	module "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

type Hysteria2Compiler struct{}

func (Hysteria2Compiler) ProtocolID() string { return "hysteria2" }
func (Hysteria2Compiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func readTLSFile(path string, private bool) ([]byte, error) {
	fail := func() ([]byte, error) {
		return nil, identity.Err(identity.Invalid, "TLS material unavailable or unsafe")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return fail()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 65536 {
		return fail()
	}
	if private && runtime.GOOS == "linux" {
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() || info.Mode().Perm()&0077 != 0 || parent.Mode().Perm()&0077 != 0 {
			return fail()
		}
		if !ownedTLSFile(info) || !ownedTLSFile(parent) {
			return fail()
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return fail()
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return fail()
	}
	b, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(b) > 65536 {
		return fail()
	}
	return b, nil
}
func (Hysteria2Compiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := (Hysteria2Compiler{}).Supports(in); err != nil {
		return nil, err
	}
	settings, _ := module.Decode(in.Inbound.Settings.Data)
	cert, err := readTLSFile(settings.TLS.CertificateFile, false)
	if err != nil {
		return nil, err
	}
	key, err := readTLSFile(settings.TLS.PrivateKeyFile, true)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid TLS certificate or private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid TLS certificate")
	}
	roots, _ := module.CAPool(settings.TLS.CACertificate)
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, identity.Err(identity.Invalid, "invalid TLS certificate chain")
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: settings.TLS.ServerName, Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, identity.Err(identity.Invalid, "TLS certificate identity or trust invalid")
	}
	if leaf.IsCA {
		return nil, identity.Err(identity.Invalid, "TLS server certificate must be a leaf")
	}
	// Include the explicit CA for clients using verified non-leaf CA pinning.
	cert = append(cert, []byte("\n"+settings.TLS.CACertificate)...)
	h := &Hysteria2Handle{endpoint: in.Inbound.Listeners[0].Endpoint, inboundID: in.Inbound.ID, total: &meter{}, users: map[string]*meter{}}
	users := make([]option.Hysteria2User, len(in.Bindings))
	for n, b := range in.Bindings {
		name := string(b.ID)
		h.users[name] = &meter{}
		users[n] = option.Hysteria2User{Name: name, Password: in.Credentials[n].Payload.(access.PasswordPayload).Password.Reveal()}
	}
	runtimeCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h.cancel = cancel
	runtimeCtx = service.ContextWith[adapter.PlatformInterface](runtimeCtx, serverPlatform{})
	ir := inbound.NewRegistry()
	inbound.Register[option.Hysteria2InboundOptions](ir, "hysteria2", func(ctx context.Context, r adapter.Router, l log.ContextLogger, tag string, o option.Hysteria2InboundOptions) (adapter.Inbound, error) {
		h.router = r
		config, err := boxtls.NewServer(ctx, l, *o.TLS)
		if err != nil {
			return nil, err
		}
		h.tls = config
		// Compose the exact service used by the stock inbound. No protocol wire is copied.
		hs, err := hysteria2.NewService[string](hysteria2.ServiceOptions{Context: ctx, Logger: l, TLSConfig: config, IgnoreClientBandwidth: true, UDPTimeout: 5 * time.Second, Handler: h})
		if err != nil {
			_ = config.Close()
			return nil, err
		}
		names, passwords := []string{}, []string{}
		for _, u := range o.Users {
			names = append(names, u.Name)
			passwords = append(passwords, u.Password)
		}
		hs.UpdateUsers(names, passwords)
		h.service = hs
		return &hysteriaOwnedInbound{Adapter: inbound.NewAdapter("hysteria2", tag), h: h}, nil
	})
	or := outbound.NewRegistry()
	direct.RegisterOutbound(or)
	dr := dns.NewTransportRegistry()
	local.RegisterTransport(dr)
	runtimeCtx = box.Context(runtimeCtx, ir, or, endpoint.NewRegistry(), dr, boxservice.NewRegistry(), certificate.NewRegistry())
	b, err := box.New(box.Options{Context: runtimeCtx, Options: option.Options{Log: &option.LogOptions{Disabled: true}, Inbounds: []option.Inbound{{Type: "hysteria2", Tag: string(in.Inbound.ID), Options: &option.Hysteria2InboundOptions{Users: users, InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{Enabled: true, ServerName: settings.TLS.ServerName, Certificate: []string{string(cert)}, Key: []string{string(key)}, MinVersion: "1.3"}}}}}}})
	if err != nil {
		cancel()
		if h.service != nil {
			_ = h.service.Close()
		}
		if h.tls != nil {
			_ = h.tls.Close()
		}
		return nil, identity.Err(identity.Unavailable, "native Hysteria2 construction failed")
	}
	h.box = b
	b.Router().AppendTracker(h)
	return h, nil
}

type Hysteria2Handle struct {
	lifecycle       sync.Mutex
	box             *box.Box
	router          adapter.Router
	service         *hysteria2.Service[string]
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

func (h *Hysteria2Handle) Start(ctx context.Context) error {
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
		return identity.Err(identity.Unavailable, "Hysteria2 runtime start failed")
	}
	h.started = true
	return nil
}
func (h *Hysteria2Handle) Health(ctx context.Context) error {
	if ctx.Err() != nil || !h.running.Load() {
		return identity.Err(identity.Unavailable, "QUIC listener is not healthy")
	}
	return nil
}
func (h *Hysteria2Handle) Activate()          { h.admitted.Store(true) }
func (h *Hysteria2Handle) Stats() ports.Stats { return h.total.snapshot() }
func (h *Hysteria2Handle) BindingStats(id identity.ID) ports.Stats {
	if m := h.users[string(id)]; m != nil {
		return m.snapshot()
	}
	return ports.Stats{}
}
func (h *Hysteria2Handle) Close(ctx context.Context) error {
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
		return identity.Err(identity.Unavailable, "Hysteria2 shutdown failed")
	}
	return nil
}

type hysteriaOwnedInbound struct {
	inbound.Adapter
	h *Hysteria2Handle
}

func (o *hysteriaOwnedInbound) Start(stage adapter.StartStage) error {
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
func (o *hysteriaOwnedInbound) Close() error {
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
	h *Hysteria2Handle
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
func (h *Hysteria2Handle) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		_ = c.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	h.router.RouteConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: "hysteria2", User: user, Source: src, Destination: dst}, onClose)
}
func (h *Hysteria2Handle) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	user, ok := auth.UserFromContext[string](ctx)
	if !ok || h.users[user] == nil || !h.admitted.Load() {
		_ = c.Close()
		if onClose != nil {
			onClose(nil)
		}
		return
	}
	h.router.RoutePacketConnectionEx(ctx, c, adapter.InboundContext{Inbound: string(h.inboundID), InboundType: "hysteria2", User: user, Source: src, Destination: dst}, onClose)
}
func (h *Hysteria2Handle) RoutedConnection(_ context.Context, c net.Conn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) net.Conn {
	return meteredConn(c, h.total, h.users[m.User])
}
func (h *Hysteria2Handle) RoutedPacketConnection(_ context.Context, c N.PacketConn, m adapter.InboundContext, _ adapter.Rule, _ adapter.Outbound) N.PacketConn {
	return meteredPacket(c, h.total, h.users[m.User])
}
func (h *Hysteria2Handle) RoutedFlow(context.Context, adapter.InboundContext, adapter.Rule, adapter.Outbound) tun.FlowTracker {
	return nil
}
