package underlay

import (
	"context"
	"fmt"
	"net/netip"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
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
