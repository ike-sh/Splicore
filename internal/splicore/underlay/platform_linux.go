//go:build linux

package underlay

import (
	"context"
	"os"
	"syscall"

	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"golang.org/x/sys/unix"
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

// KernelTransportMark protects kernel-owned UDP sockets with the same mark as
// userspace sockets. Existing hostnetwork owns and verifies any TUN bypass
// rules; this method creates no host state.
func (f *Factory) KernelTransportMark(ctx context.Context) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if f == nil || f.backend == nil {
		return 0, unsafe("missing kernel underlay capability")
	}
	if f.Required() {
		if !f.backend.Capabilities().MarkTable || f.degraded.Load() {
			return 0, unsafe("kernel transport mark unavailable")
		}
		if err := f.verify(ctx); err != nil {
			return 0, err
		}
	}
	return hostnetwork.SocketMark, nil
}
