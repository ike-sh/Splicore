//go:build linux

package underlay

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

type linuxBackend struct{}

func platformBackend() Backend { return linuxBackend{} }
func (linuxBackend) Capabilities() Capabilities {
	return Capabilities{Strategy: "socket-mark-and-journaled-daemon-uid", PerSocket: true, MarkTable: true, SystemResolver: true}
}
func (linuxBackend) Protect(_ context.Context, _ Scope, _, _ string, r syscall.RawConn) error {
	var socketErr error
	if err := r.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(hostnetwork.SocketMark))
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return os.NewSyscallError("setsockopt SO_MARK", socketErr)
	}
	return nil
}
func (linuxBackend) Reconcile(context.Context, []Endpoint) error { return nil }

// Host-network Prepare verifies the UID/mark rules before publishing TUN. The
// socket control performs the native setsockopt check on each new socket.
func (linuxBackend) Verify(ctx context.Context) error { return ctx.Err() }
