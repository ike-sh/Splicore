// Package underlay protects runtime sockets after logical routing has selected
// an action. It never selects DIRECT, a proxy, a policy group or a DNS server.
package underlay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type Purpose uint8

const (
	DirectEgress Purpose = iota + 1
	ProxyUnderlay
	ServerTarget
	DNSBootstrap
	DNSUpstream
	HealthProbe
	SystemDNS
	LocalControl
	ProviderFetch
)

type Scope struct {
	Purpose    Purpose
	Runtime    identity.ID
	Generation identity.ID
}

type Capabilities struct {
	Strategy         string `json:"strategy"`
	PerSocket        bool   `json:"per_socket"`
	EndpointRoutes   bool   `json:"endpoint_routes"`
	InterfaceBinding bool   `json:"interface_binding"`
	MarkTable        bool   `json:"mark_table"`
	SystemResolver   bool   `json:"system_resolver"`
}

// Endpoint is bounded infrastructure state, never arbitrary user destinations.
type Endpoint struct {
	Scope   Scope
	Address netip.Addr
}

// Backend owns platform mechanics and durable mutation/readback. Reconcile is
// transactional: on error it preserves the previous effective set or cleanup debt.
type Backend interface {
	Capabilities() Capabilities
	Protect(context.Context, Scope, string, string, syscall.RawConn) error
	Reconcile(context.Context, []Endpoint) error
	Verify(context.Context) error
}

type Status struct {
	Capabilities
	Health       string        `json:"health"`
	Generations  []identity.ID `json:"active_generations"`
	ActiveLeases int           `json:"active_leases"`
	Endpoints    int           `json:"infrastructure_endpoints"`
	Acquires     uint64        `json:"acquires,string"`
	Releases     uint64        `json:"releases,string"`
	Failures     uint64        `json:"reconcile_failures,string"`
	Unprotected  int           `json:"unprotected_required_runtimes"`
	LastError    string        `json:"last_error,omitempty"`
}

type Factory struct {
	hostVerifier                 atomic.Pointer[hostVerification]
	mu                           sync.Mutex // control metadata only; never held during socket/data I/O
	backend                      Backend
	leases                       map[identity.ID]*Lease
	required                     atomic.Int64
	degraded                     atomic.Bool
	acquires, releases, failures atomic.Uint64
}
type hostVerification struct{ verify func(context.Context) error }

func (f *Factory) SetHostVerifier(verify func(context.Context) error) {
	if verify == nil {
		f.hostVerifier.Store(nil)
	} else {
		f.hostVerifier.Store(&hostVerification{verify})
	}
}
func (f *Factory) verify(ctx context.Context) error {
	if err := f.backend.Verify(ctx); err != nil {
		return err
	}
	if v := f.hostVerifier.Load(); v != nil {
		return v.verify(ctx)
	}
	return nil
}

// New starts without TUN and performs no host mutation or privilege check.
func New() *Factory { return NewWithBackend(platformBackend()) }
func NewWithBackend(b Backend) *Factory {
	return &Factory{backend: b, leases: map[identity.ID]*Lease{}}
}

func (f *Factory) Required() bool { return f.required.Load() > 0 }

// RetainDebt prevents new protected sockets after a retirement could not prove
// that its adapter/socket cleanup completed. Existing generation refs survive.
func (f *Factory) RetainDebt() {
	f.degraded.Store(true)
	f.failures.Add(1)
}

type contextKey struct{}
type scopeKey struct{}
type purposeKey struct{}

func WithPurpose(ctx context.Context, p Purpose) context.Context {
	return context.WithValue(ctx, purposeKey{}, p)
}
func PurposeFrom(ctx context.Context, fallback Purpose) Purpose {
	p, _ := ctx.Value(purposeKey{}).(Purpose)
	if p == 0 {
		return fallback
	}
	return p
}

func WithFactory(ctx context.Context, f *Factory) context.Context {
	return context.WithValue(ctx, contextKey{}, f)
}
func FromContext(ctx context.Context) (*Factory, error) {
	f, _ := ctx.Value(contextKey{}).(*Factory)
	if f == nil || f.backend == nil {
		return nil, unsafe("missing underlay capability")
	}
	return f, nil
}
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}
func ScopeFrom(ctx context.Context, purpose Purpose) Scope {
	s, _ := ctx.Value(scopeKey{}).(Scope)
	s.Purpose = purpose
	return s
}
func unsafe(message string) error {
	return identity.Err(identity.Unavailable, "unsafe_underlay: "+message)
}

type Lease struct {
	f         *Factory
	ID        identity.ID
	required  bool
	endpoints []Endpoint // immutable replacement under f.mu
	released  bool
}

func (l *Lease) RetainDebt() { l.f.RetainDebt() }

// Begin pins the protection mode before bootstrap/build. The caller publishes
// only after host-network preparation has also passed its readback gate.
func (f *Factory) Begin(ctx context.Context, required bool) (*Lease, error) {
	if f == nil || f.backend == nil {
		return nil, unsafe("missing underlay backend")
	}
	id, err := identity.NewID()
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if required {
		c := f.backend.Capabilities()
		if !c.PerSocket {
			return nil, unsafe("required runtime protection unavailable")
		}
		if f.degraded.Load() {
			return nil, unsafe("protection degraded")
		}
		if err = f.verify(ctx); err != nil {
			return nil, err
		}
	}
	l := &Lease{f: f, ID: id, required: required}
	f.leases[id] = l
	if required {
		f.required.Add(1)
	}
	f.acquires.Add(1)
	return l, nil
}

func Normalize(addresses []netip.Addr) ([]netip.Addr, error) {
	if len(addresses) == 0 || len(addresses) > 32 {
		return nil, identity.Err(identity.Invalid, "empty or oversized resolved endpoint set")
	}
	seen := map[netip.Addr]bool{}
	out := []netip.Addr{}
	for _, a := range addresses {
		a = a.Unmap()
		if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
			return nil, identity.Err(identity.Invalid, "invalid underlay endpoint")
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out, nil
}

func (f *Factory) effectiveLocked() []Endpoint {
	all := []Endpoint{}
	for _, l := range f.leases {
		if !l.released && l.required {
			all = append(all, l.endpoints...)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Address != all[j].Address {
			return all[i].Address.Less(all[j].Address)
		}
		return all[i].Scope.Runtime < all[j].Scope.Runtime
	})
	return all
}

// AddEndpoint provisions desired infrastructure together with every retained
// generation. Callers resolve fresh even when the canonical node is unchanged.
func (l *Lease) AddEndpoint(ctx context.Context, s Scope, addresses []netip.Addr) error {
	if l == nil || l.f == nil {
		return identity.Err(identity.Invalid, "missing endpoint lease")
	}
	ips, err := Normalize(addresses)
	if err != nil {
		return err
	}
	if s.Purpose != ProxyUnderlay && s.Purpose != DNSBootstrap && s.Purpose != DNSUpstream && s.Purpose != HealthProbe && s.Purpose != ProviderFetch {
		return identity.Err(identity.Invalid, "arbitrary target cannot own endpoint routes")
	}
	f := l.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if l.released || f.leases[l.ID] != l {
		return identity.Err(identity.Conflict, "underlay generation retired")
	}
	s.Generation = l.ID
	prior := l.endpoints
	next := append([]Endpoint(nil), prior...)
	for _, ip := range ips {
		if !ip.IsLoopback() {
			e := Endpoint{Scope: s, Address: ip}
			found := false
			for _, old := range next {
				if old == e {
					found = true
					break
				}
			}
			if !found {
				next = append(next, e)
			}
		}
	}
	if len(next) == len(prior) {
		return nil
	}
	if len(next) > 1024 {
		return identity.Err(identity.Invalid, "infrastructure endpoint limit exceeded")
	}
	l.endpoints = next
	if l.required {
		if err = f.backend.Reconcile(ctx, f.effectiveLocked()); err == nil {
			err = f.backend.Verify(ctx)
		}
		if err != nil {
			l.endpoints = prior
			f.failures.Add(1)
			// Restore the old effective set, including new partial apply debt.
			cleanup := context.WithoutCancel(ctx)
			if restoreErr := f.backend.Reconcile(cleanup, f.effectiveLocked()); restoreErr != nil {
				f.degraded.Store(true)
				err = errors.Join(err, restoreErr)
			}
			return err
		}
	}
	return nil
}

// Close follows the last generation/socket retirement. Failure retains the
// logical reference and journal debt; a later Close can finish cleanup.
func (l *Lease) Close() error {
	if l == nil {
		return nil
	}
	if l.f == nil {
		return identity.Err(identity.Invalid, "unknown underlay lease")
	}
	f := l.f
	f.mu.Lock()
	defer f.mu.Unlock()
	if l.released {
		return nil
	}
	if f.leases[l.ID] != l {
		return identity.Err(identity.Conflict, "unknown underlay lease")
	}
	l.released = true
	if l.required {
		if err := f.backend.Reconcile(context.Background(), f.effectiveLocked()); err != nil {
			l.released = false
			f.degraded.Store(true)
			f.failures.Add(1)
			return err
		}
		f.required.Add(-1)
	}
	delete(f.leases, l.ID)
	f.releases.Add(1)
	return nil
}

type Dialer struct {
	f     *Factory
	scope Scope
}

func (f *Factory) New(s Scope) (*Dialer, error) {
	if f == nil || f.backend == nil || s.Purpose < DirectEgress || s.Purpose > ProviderFetch {
		return nil, unsafe("invalid dial capability")
	}
	if f.required.Load() > 0 && !f.backend.Capabilities().PerSocket {
		return nil, unsafe("per-socket protection unavailable")
	}
	return &Dialer{f: f, scope: s}, nil
}
func DialerFrom(ctx context.Context, p Purpose) (*Dialer, error) {
	f, e := FromContext(ctx)
	if e != nil {
		return nil, e
	}
	return f.New(ScopeFrom(ctx, p))
}

func (d *Dialer) Control(network, address string, raw syscall.RawConn) error {
	if d == nil || d.f == nil {
		return unsafe("missing dial capability")
	}
	if d.scope.Purpose == LocalControl {
		host, _, err := net.SplitHostPort(address)
		ip, e := netip.ParseAddr(host)
		if err != nil || e != nil || !ip.IsLoopback() {
			return unsafe("non-local control endpoint")
		}
		return nil
	}
	if d.f.required.Load() == 0 {
		return nil
	}
	if d.scope.Purpose == SystemDNS {
		host, _, err := net.SplitHostPort(address)
		ip, e := netip.ParseAddr(host)
		if err != nil || e != nil || ip.IsLoopback() {
			return unsafe("system DNS stub may recurse through interception; configure explicit bootstrap DNS")
		}
	}
	if d.f.degraded.Load() {
		return unsafe("protection degraded")
	}
	if err := d.f.verify(context.Background()); err != nil {
		d.f.degraded.Store(true)
		return unsafe("protection verification failed")
	}
	if err := d.f.backend.Protect(context.Background(), d.scope, network, address, raw); err != nil {
		d.f.degraded.Store(true)
		d.f.failures.Add(1)
		return unsafe("socket protection failed")
	}
	return nil
}

func (d *Dialer) Resolver() *net.Resolver {
	system := *d
	system.scope.Purpose = SystemDNS
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		// Numeric OS DNS endpoints only: no recursive host resolution.
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if _, err = netip.ParseAddr(host); err != nil {
			return nil, unsafe("non-numeric system DNS endpoint")
		}
		return system.dialNumeric(ctx, network, address)
	}}
}
func (d *Dialer) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if d.f.required.Load() == 0 {
		return net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	if d.f.required.Load() > 0 && !d.f.backend.Capabilities().SystemResolver {
		return nil, unsafe("system resolver cannot guarantee bypass; configure explicit bootstrap DNS")
	}
	return d.Resolver().LookupNetIP(ctx, network, host)
}
func (d *Dialer) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	if d.f.required.Load() == 0 {
		return net.DefaultResolver.LookupIP(ctx, network, host)
	}
	ips, err := d.LookupNetIP(ctx, network, host)
	out := []net.IP{}
	for _, ip := range ips {
		out = append(out, net.IP(ip.AsSlice()))
	}
	return out, err
}
func (d *Dialer) dialNumeric(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Control: d.Control}).DialContext(ctx, network, address)
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil {
		return nil, unsafe("missing dial capability")
	}
	if d.f.required.Load() == 0 {
		return (&net.Dialer{Control: d.Control}).DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, identity.Err(identity.Invalid, "invalid runtime endpoint")
	}
	if _, err = netip.ParseAddr(host); err == nil {
		return d.dialNumeric(ctx, network, address)
	}
	ips, err := d.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, unsafe("empty endpoint resolution")
	}
	// Dial only the bootstrap snapshot; never re-enter an unprotected resolver.
	var last error
	for _, ip := range ips {
		conn, e := d.dialNumeric(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}
func (d *Dialer) ListenPacket(ctx context.Context, network, local, remote string) (net.PacketConn, error) {
	if d == nil {
		return nil, unsafe("missing packet capability")
	}
	return (&net.ListenConfig{Control: func(n, a string, r syscall.RawConn) error {
		if remote != "" {
			a = remote
		}
		return d.Control(n, a, r)
	}}).ListenPacket(ctx, network, local)
}

func (f *Factory) Status() Status {
	if f.required.Load() > 0 && f.verify(context.Background()) != nil {
		f.degraded.Store(true)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Status{Capabilities: f.backend.Capabilities(), Health: "healthy", Generations: []identity.ID{}, ActiveLeases: len(f.leases), Acquires: f.acquires.Load(), Releases: f.releases.Load(), Failures: f.failures.Load()}
	seen := map[netip.Addr]bool{}
	for id, l := range f.leases {
		s.Generations = append(s.Generations, id)
		for _, e := range l.endpoints {
			seen[e.Address] = true
		}
	}
	s.Endpoints = len(seen)
	sort.Slice(s.Generations, func(i, j int) bool { return s.Generations[i] < s.Generations[j] })
	if f.degraded.Load() {
		s.Health = "degraded"
		s.LastError = "underlay_verification_failed"
		s.Unprotected = len(f.leases)
	}
	return s
}

func EndpointAddress(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
