//go:build linux

package underlay

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/hostnetwork"
	"github.com/sagernet/sing/common/control"
	"net/netip"
	"os"
	"strings"
	"syscall"
)

type linuxBackend struct{}

func platformBackend() Backend { return linuxBackend{} }
func (linuxBackend) Capabilities() Capabilities {
	return Capabilities{Strategy: "socket-mark-and-journaled-daemon-uid", PerSocket: true, MarkTable: true, Child: true, SystemResolver: true}
}
func (linuxBackend) Protect(_ context.Context, _ Scope, n, a string, r syscall.RawConn) error {
	return control.RoutingMark(hostnetwork.SocketMark)(n, a, r)
}
func (linuxBackend) Reconcile(context.Context, []Endpoint) error { return nil }

// Host-network Prepare verifies the UID/mark rules before publishing TUN. The
// socket control performs the native setsockopt check on each new socket.
func (linuxBackend) Verify(ctx context.Context) error { return ctx.Err() }

func (linuxBackend) VerifyChild(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return unsafe("child system resolver unavailable")
	}
	return verifyChildResolver(string(b))
}

// A system stub runs under a different UID and can forward queries into the
// intercepted DNS path. Only numeric, non-local upstreams inherit the daemon
// UID bypass. No resolver choice or protocol artifact is changed here.
func verifyChildResolver(config string) error {
	count := 0
	for _, line := range strings.Split(config, "\n") {
		fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(fields) == 0 || fields[0] != "nameserver" {
			continue
		}
		if len(fields) != 2 {
			return unsafe("invalid child system resolver")
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return unsafe("child system DNS stub cannot guarantee bypass")
		}
		count++
	}
	if count == 0 {
		return unsafe("child requires an explicit system DNS upstream")
	}
	return nil
}
