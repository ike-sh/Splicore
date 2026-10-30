// Package wireguardendpoint owns a symmetric userspace L3 WireGuard endpoint.
// The official engine authenticates packets; Splicore owns DNS, IP flows and
// their routing, lifecycle and credential metadata.
package wireguardendpoint

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
	"github.com/ike-sh/Splicore/internal/splicore/nativetun"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"golang.zx2c4.com/wireguard/device"
)

type Identity struct {
	EndpointTag   string `json:"endpoint_tag"`
	PeerPublicKey string `json:"peer_public_key"`
}
type identityKey struct{}

func PeerIdentity(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

type Options struct {
	LookupHost     func(context.Context, string) ([]netip.Addr, error)
	LookupEndpoint func(context.Context, string) ([]netip.Addr, error)
	Dispatcher     nativetun.Dispatcher
	Underlay       *underlay.Factory
}
type State string

const (
	Created  State = "CREATED"
	Starting State = "STARTING"
	Active   State = "ACTIVE"
	Closing  State = "CLOSING"
	Closed   State = "CLOSED"
)

type route struct {
	prefix    netip.Prefix
	publicKey string
}
type Endpoint struct {
	operation     sync.Mutex
	pending       *clientio.Owner
	config        E.WireGuard
	options       Options
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	state         State
	device        *device.Device
	bind          *udpBind
	tun           *memoryTUN
	stack         *nativetun.Runtime
	backend       WireGuardBackend
	backendStatus BackendStatus
	kernelFactory func(*Endpoint, E.WireGuard) (WireGuardBackend, error)
	routes        []route
	addresses     []netip.Addr
	err           error
}

func New(parent context.Context, config E.WireGuard, options Options) (*Endpoint, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if (!nativetun.Included && config.RequestedBackend() == E.Userspace) || options.Dispatcher == nil || options.Underlay == nil {
		return nil, nativetun.ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	e := &Endpoint{config: config.Clone(), options: options, ctx: ctx, cancel: cancel, done: make(chan struct{}), state: Created, pending: clientio.New(), backendStatus: BackendStatus{Requested: config.RequestedBackend(), PeerCount: len(config.Peers)}}
	for _, raw := range config.Addresses {
		e.addresses = append(e.addresses, netip.MustParsePrefix(raw).Addr())
	}
	for _, peer := range config.Peers {
		for _, raw := range peer.AllowedIPs {
			e.routes = append(e.routes, route{netip.MustParsePrefix(raw).Masked(), peer.PublicKey})
		}
	}
	go e.shutdown()
	return e, nil
}

func (e *Endpoint) Start(ctx context.Context) error {
	e.operation.Lock()
	if e.state != Created {
		e.operation.Unlock()
		return errors.New("WireGuard endpoint already started or closed")
	}
	err := e.startLocked(ctx)
	e.operation.Unlock()
	if err != nil {
		_ = e.Close()
	}
	return err
}

func (e *Endpoint) startLocked(ctx context.Context) error {
	if e.state != Created || e.ctx.Err() != nil {
		return net.ErrClosed
	}
	e.state = Starting
	request, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	defer func() { stop(); cancel() }()
	resolved := e.config.Clone()
	for i, peer := range resolved.Peers {
		if peer.Endpoint == "" {
			continue
		}
		host, port, _ := E.SplitEndpoint(peer.Endpoint)
		ips, err := e.resolveWith(request, host, e.options.LookupEndpoint)
		if err != nil {
			return err
		}
		resolved.Peers[i].Endpoint = netip.AddrPortFrom(ips[0], port).String()
	}
	e.backendStatus = BackendStatus{Requested: e.config.RequestedBackend(), PeerCount: len(resolved.Peers)}
	if e.config.RequestedBackend() != E.Userspace {
		factory := e.kernelFactory
		if factory == nil {
			factory = newKernelBackend
		}
		b, err := factory(e, resolved)
		if err == nil && b == nil {
			err = &BackendError{Class: RuntimeFailure, Operation: "nil kernel backend"}
		}
		if err == nil {
			e.backend = b
			err = b.Prepare(request)
			if err == nil {
				err = b.Start(request)
			}
		}
		if err == nil {
			e.backendStatus.Selected = E.Kernel
			e.backendStatus.Availability = Supported
			e.state = Active
			return nil
		}
		e.backendStatus.Availability = backendAvailability(err)
		if b != nil {
			if cleanup := b.Close(); cleanup != nil {
				err = errors.Join(err, &BackendError{Class: CleanupFailure, Operation: "rollback", Cause: cleanup})
				e.backendStatus.Availability = backendAvailability(err)
				return err
			}
		}
		e.backend = nil
		if e.config.RequestedBackend() != E.Auto || !fallbackEligible(err) {
			return err
		}
	}
	if !nativetun.Included {
		return nativetun.ErrUnavailable
	}
	e.backend = &userspaceBackend{e: e, config: resolved}
	if err := e.backend.Prepare(request); err != nil {
		return err
	}
	if err := e.backend.Start(request); err != nil {
		return err
	}
	e.backendStatus.Selected = E.Userspace
	e.state = Active
	return nil
}

func (e *Endpoint) startUserspace(request context.Context, config E.WireGuard) error {
	var configuration strings.Builder
	key := config.PrivateKey.Reveal()
	fmt.Fprintf(&configuration, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", hex.EncodeToString(key[:]), config.ListenPort)
	for _, peer := range config.Peers {
		public, _ := E.DecodeKey(peer.PublicKey)
		fmt.Fprintf(&configuration, "public_key=%s\nreplace_allowed_ips=true\n", hex.EncodeToString(public[:]))
		if peer.PreSharedKey.Present() {
			psk := peer.PreSharedKey.Reveal()
			fmt.Fprintf(&configuration, "preshared_key=%s\n", hex.EncodeToString(psk[:]))
		}
		if peer.Endpoint != "" {
			host, port, _ := E.SplitEndpoint(peer.Endpoint)
			ips, err := e.resolveWith(request, host, e.options.LookupEndpoint)
			if err != nil {
				return err
			}
			fmt.Fprintf(&configuration, "endpoint=%s\n", netip.AddrPortFrom(ips[0], port))
		}
		fmt.Fprintf(&configuration, "persistent_keepalive_interval=%d\n", peer.PersistentKeepaliveInterval)
		for _, allowed := range peer.AllowedIPs {
			fmt.Fprintf(&configuration, "allowed_ip=%s\n", netip.MustParsePrefix(allowed).Masked())
		}
	}
	if err := request.Err(); err != nil {
		return err
	}
	protected, err := e.options.Underlay.New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
	if err != nil {
		return err
	}
	e.tun = newMemoryTUN(e.config.InnerMTU())
	e.bind = &udpBind{protected: protected, ctx: e.ctx}
	// Upstream UAPI errors and debug messages can contain configuration material.
	// Keep this logger silent and expose only the typed operational status below.
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	e.device = device.NewDevice(e.tun, e.bind, logger)
	if err = e.device.IpcSet(configuration.String()); err != nil {
		return errors.New("WireGuard engine configuration rejected")
	}
	e.stack, err = nativetun.New(e.ctx, stackDevice{e.tun}, nativetun.Options{MTU: uint32(e.config.InnerMTU()), Addresses: e.addresses, Dispatcher: authenticatedDispatcher{e}})
	if err != nil {
		return err
	}
	if err = e.stack.Start(); err != nil {
		return err
	}
	if err = e.device.Up(); err != nil {
		return errors.New("WireGuard UDP bind unavailable")
	}
	if err = request.Err(); err != nil {
		return err
	}
	e.state = Active
	return nil
}

func (e *Endpoint) shutdown() {
	<-e.ctx.Done()
	e.pending.Close()
	e.operation.Lock()
	defer e.operation.Unlock()
	e.state = Closing
	if e.backend != nil {
		e.err = errors.Join(e.err, e.backend.Close())
	}
	e.state = Closed
	close(e.done)
}

func (e *Endpoint) closeUserspace() error {
	var err error
	if e.stack != nil {
		err = errors.Join(err, e.stack.Close())
	}
	if e.device != nil {
		e.device.Close()
		<-e.device.Wait()
		e.device = nil
	}
	if e.tun != nil {
		_ = e.tun.Close()
		e.tun.drain()
	}
	if e.bind != nil {
		err = errors.Join(err, e.bind.Close())
	}
	e.stack = nil
	return err
}
func (e *Endpoint) Close() error                        { e.cancel(); <-e.done; return e.err }
func (e *Endpoint) SupportsNetwork(network string) bool { return network == "tcp" || network == "udp" }

func (e *Endpoint) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return e.resolveWith(ctx, host, e.options.LookupHost)
}

func (e *Endpoint) resolveWith(ctx context.Context, host string, lookup func(context.Context, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	request, done, err := e.pending.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	bounded, cancel := context.WithTimeout(request, 5*time.Second)
	defer cancel()
	ctx = bounded
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lookup == nil {
		lookup = e.options.LookupHost
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if lookup == nil {
		return nil, errors.New("WireGuard requires Core DNS for domain resolution")
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, &resolutionError{err}
	}
	result := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() {
			result = append(result, ip.Unmap())
		}
	}
	if len(result) == 0 {
		return nil, errors.New("WireGuard Core DNS returned no usable address")
	}
	return result, nil
}

// peerFor is used only behind the official authenticated TUN ingress, or for
// outbound route selection. This table is immutable for the entire Device
// lifetime and exactly mirrors its AllowedIPs. The engine has already proved
// that its cryptographic peer equals the source's longest-prefix owner.
func (e *Endpoint) peerFor(ip netip.Addr) (string, bool) {
	best := -1
	key := ""
	for _, r := range e.routes {
		if r.prefix.Bits() > best && r.prefix.Contains(ip) {
			best = r.prefix.Bits()
			key = r.publicKey
		}
	}
	return key, key != ""
}

func (e *Endpoint) target(ctx context.Context, target access.Endpoint) (netip.AddrPort, netip.Addr, error) {
	if target.Validate() != nil {
		return netip.AddrPort{}, netip.Addr{}, E.ErrInvalid
	}
	ips, err := e.resolve(ctx, target.Host)
	if err != nil {
		return netip.AddrPort{}, netip.Addr{}, err
	}
	for _, ip := range ips {
		local := netip.Addr{}
		own := false
		for _, address := range e.addresses {
			if address == ip {
				own = true
			}
			if !local.IsValid() && address.Is4() == ip.Is4() {
				local = address
			}
		}
		if own || !local.IsValid() {
			continue
		}
		if _, ok := e.peerFor(ip); ok {
			return netip.AddrPortFrom(ip, target.Port), local, nil
		}
	}
	return netip.AddrPort{}, netip.Addr{}, errors.New("WireGuard destination has no AllowedIPs route")
}

func (e *Endpoint) activeBackend() (WireGuardBackend, error) {
	e.operation.Lock()
	defer e.operation.Unlock()
	if e.state != Active || e.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	return e.backend, nil
}

func (e *Endpoint) DialContext(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	request, done, err := e.pending.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	ctx = request
	stack, err := e.activeBackend()
	if err != nil {
		return nil, err
	}
	remote, local, err := e.target(ctx, target)
	if err != nil {
		return nil, err
	}
	return stack.DialTCP(ctx, local, remote)
}

func (e *Endpoint) ListenPacket(ctx context.Context, target access.Endpoint) (net.PacketConn, error) {
	request, done, err := e.pending.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	ctx = request
	stack, err := e.activeBackend()
	if err != nil {
		return nil, err
	}
	_, local, err := e.target(ctx, target)
	if err != nil {
		return nil, err
	}
	packet, err := stack.ListenUDP(ctx, local)
	if err != nil {
		return nil, err
	}
	return newRoutedPacket(packet, e, local)
}

// Keep resolver diagnostics out of status/errors while preserving error identity.
type resolutionError struct{ cause error }

func (e *resolutionError) Error() string { return "WireGuard Core DNS resolution failed" }
func (e *resolutionError) Unwrap() error { return e.cause }

type authenticatedDispatcher struct{ endpoint *Endpoint }

func (d authenticatedDispatcher) identity(ctx context.Context, source netip.AddrPort) (context.Context, bool) {
	for _, local := range d.endpoint.addresses {
		if source.Addr() == local {
			return ctx, false
		}
	}
	key, ok := d.endpoint.peerFor(source.Addr())
	if !ok {
		return ctx, false
	}
	return context.WithValue(ctx, identityKey{}, Identity{d.endpoint.config.Tag, key}), true
}

func (d authenticatedDispatcher) TCP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	ctx, ok := d.identity(ctx, source)
	if !ok {
		_ = c.Close()
		return
	}
	d.endpoint.options.Dispatcher.TCP(ctx, c, source, destination)
}

func (d authenticatedDispatcher) UDP(ctx context.Context, c net.Conn, source, destination netip.AddrPort) {
	ctx, ok := d.identity(ctx, source)
	if !ok {
		_ = c.Close()
		return
	}
	d.endpoint.options.Dispatcher.UDP(ctx, c, source, destination)
}

type PeerStatus struct {
	PublicKey          string    `json:"public_key"`
	ConfiguredEndpoint string    `json:"configured_endpoint,omitempty"`
	CurrentEndpoint    string    `json:"current_endpoint,omitempty"`
	LastHandshake      time.Time `json:"last_handshake,omitzero"`
	RXBytes            uint64    `json:"rx_bytes"`
	TXBytes            uint64    `json:"tx_bytes"`
	Keepalive          int       `json:"persistent_keepalive_interval"`
	AllowedIPs         []string  `json:"allowed_ips"`
}
type Status struct {
	BackendStatus
	Tag           string       `json:"tag"`
	State         State        `json:"state"`
	Addresses     []string     `json:"addresses"`
	MTU           int          `json:"mtu"`
	ListenPort    int          `json:"listen_port"`
	UDPResources  int          `json:"udp_resources"`
	QueuedPackets int          `json:"queued_packets"`
	Peers         []PeerStatus `json:"peers"`
}

func (e *Endpoint) Status() Status {
	e.operation.Lock()
	defer e.operation.Unlock()
	status := Status{BackendStatus: e.backendStatus, Tag: e.config.Tag, State: e.state, Addresses: append([]string(nil), e.config.Addresses...), MTU: e.config.InnerMTU(), ListenPort: e.config.ListenPort, Peers: make([]PeerStatus, len(e.config.Peers))}
	for i, p := range e.config.Peers {
		status.Peers[i] = PeerStatus{PublicKey: p.PublicKey, ConfiguredEndpoint: p.Endpoint, Keepalive: p.PersistentKeepaliveInterval, AllowedIPs: append([]string(nil), p.AllowedIPs...)}
	}
	if e.backend != nil && e.state != Closed {
		e.backend.Status(&status)
	}
	return status
}

func (e *Endpoint) userspaceStatus(status *Status) {
	peers := map[string]*PeerStatus{}
	for i, p := range status.Peers {
		key, _ := E.DecodeKey(p.PublicKey)
		peers[hex.EncodeToString(key[:])] = &status.Peers[i]
	}
	if e.bind != nil {
		status.UDPResources = e.bind.resources()
	}
	if e.tun != nil {
		status.QueuedPackets = len(e.tun.decrypted) + len(e.tun.plaintext)
	}
	if e.device == nil || e.state == Closed {
		return
	}
	raw, err := e.device.IpcGet()
	if err != nil {
		return
	}
	var current *PeerStatus
	var seconds int64
	for line := range strings.SplitSeq(raw, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "listen_port":
			status.ListenPort, _ = strconv.Atoi(v)
		case "public_key":
			current = peers[v]
			seconds = 0
		case "endpoint":
			if current != nil {
				current.CurrentEndpoint = v
			}
		case "rx_bytes":
			if current != nil {
				current.RXBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "tx_bytes":
			if current != nil {
				current.TXBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(v, 10, 64)
		case "last_handshake_time_nsec":
			nanoseconds, _ := strconv.ParseInt(v, 10, 64)
			if current != nil && seconds != 0 {
				current.LastHandshake = time.Unix(seconds, nanoseconds)
			}
		}
	}
}
