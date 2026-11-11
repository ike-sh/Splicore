package native

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"sync/atomic"
	"syscall"
)

type trustTunnelDenyBackend struct{ attempts atomic.Int32 }

func (*trustTunnelDenyBackend) Capabilities() underlay.Capabilities {
	return underlay.Capabilities{PerSocket: true, SystemResolver: true}
}
func (b *trustTunnelDenyBackend) Protect(_ context.Context, s underlay.Scope, _, _ string, _ syscall.RawConn) error {
	if s.Purpose == underlay.ServerTarget {
		b.attempts.Add(1)
		return errors.New("synthetic host egress policy denial")
	}
	return nil
}
func (*trustTunnelDenyBackend) Reconcile(context.Context, []underlay.Endpoint) error { return nil }
func (*trustTunnelDenyBackend) Verify(context.Context) error                         { return nil }
