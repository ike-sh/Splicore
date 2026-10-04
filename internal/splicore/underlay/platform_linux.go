//go:build linux

package underlay

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing/common/control"
	"syscall"
)

type linuxBackend struct{}

func platformBackend() Backend { return linuxBackend{} }
func (linuxBackend) Capabilities() Capabilities {
	return Capabilities{Strategy: "socket-mark-and-journaled-daemon-uid", PerSocket: true, MarkTable: true, SystemResolver: true}
}
func (linuxBackend) Protect(_ context.Context, _ Scope, n, a string, r syscall.RawConn) error {
	return control.RoutingMark(hostnetwork.SocketMark)(n, a, r)
}
func (linuxBackend) Reconcile(context.Context, []Endpoint) error { return nil }

// Host-network Prepare verifies the UID/mark rules before publishing TUN. The
// socket control performs the native setsockopt check on each new socket.
func (linuxBackend) Verify(ctx context.Context) error { return ctx.Err() }
