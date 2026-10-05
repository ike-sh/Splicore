package underlay

import (
	"context"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing/common/control"
)

// WindowsBackend combines per-socket interface protection with the existing
// durable infrastructure-route reconciler. It is only supplied after platform
// qualification; tests supply the identical contract with a fake host backend.
type WindowsBackend struct {
	Lease         *hostnetwork.Lease
	Underlays     map[bool]hostnetwork.WindowsUnderlay
	SocketControl func(context.Context, Scope, string, string, syscall.RawConn) error
	Readback      func(context.Context) error
}

func (b *WindowsBackend) Capabilities() Capabilities {
	return Capabilities{Strategy: "interface-and-endpoint-leases", PerSocket: b.SocketControl != nil, EndpointRoutes: true, InterfaceBinding: true}
}
func (b *WindowsBackend) Protect(ctx context.Context, s Scope, n, a string, r syscall.RawConn) error {
	if b.SocketControl == nil {
		return unsafe("missing Windows per-socket capability")
	}
	return b.SocketControl(ctx, s, n, a, r)
}
func (b *WindowsBackend) Verify(ctx context.Context) error {
	if b.Lease == nil || b.SocketControl == nil || b.Readback == nil {
		return unsafe("unverified Windows underlay")
	}
	return b.Readback(ctx)
}
func (b *WindowsBackend) Reconcile(ctx context.Context, endpoints []Endpoint) error {
	d := make([]hostnetwork.WindowsDependency, 0, len(endpoints))
	for i, e := range endpoints {
		reason := "node"
		switch e.Scope.Purpose {
		case DNSBootstrap:
			reason = "dns-bootstrap"
		case DNSUpstream:
			reason = "dns-upstream"
		case HealthProbe:
			reason = "health"
		}
		d = append(d, hostnetwork.WindowsDependency{ID: fmt.Sprintf("lease:%s:%d", e.Scope.Generation, i), Reason: reason, Addresses: []netip.Addr{e.Address}})
	}
	p, err := hostnetwork.BuildWindowsBypassPlan(ctx, d, b.Underlays, nil)
	if err != nil {
		return err
	}
	return b.Lease.ReconcileWindowsBypass(ctx, p)
}

// InterfaceControl reuses sing's public binding primitive, including its Windows
// IP_UNICAST_IF/IPV6_UNICAST_IF handling. Native adapters reuse the same primitive
// through their protected NetworkManager rather than duplicating socket code.
func InterfaceControl(finder control.InterfaceFinder, name string, index int) func(context.Context, Scope, string, string, syscall.RawConn) error {
	bind := control.BindToInterface(finder, name, index)
	return func(_ context.Context, _ Scope, n, a string, r syscall.RawConn) error { return bind(n, a, r) }
}
