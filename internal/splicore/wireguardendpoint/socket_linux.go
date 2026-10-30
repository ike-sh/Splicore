//go:build linux

package wireguardendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Called only inside the namespace executor. The os.File owns the original
// nonblocking CLOEXEC FD. FileConn/FilePacketConn duplicate it into Go's network
// poller; the original is closed on every handoff and failure path.
func indexedSocket(local netip.AddrPort, index uint32, kind int, transparent bool) (file *os.File, result error) {
	sa, err := indexedSockaddr(local, index)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_INET6, kind|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	file = os.NewFile(uintptr(fd), "wireguard-inner-ipv6")
	defer func() {
		if result != nil {
			result = errors.Join(result, cleanupError("inner socket close", file.Close()))
			file = nil
		}
	}()
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
		return file, os.NewSyscallError("ipv6-only", err)
	}
	if transparent {
		if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1); err != nil {
			return file, os.NewSyscallError("ipv6-transparent", err)
		}
		if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return file, os.NewSyscallError("reuse-address", err)
		}
	}
	if err = unix.Bind(fd, sa); err != nil {
		return file, os.NewSyscallError("bind", err)
	}
	return file, nil
}

// RawConn.Write sleeps in Go's poller after EINPROGRESS. Read SO_ERROR and
// verify getpeername on wakeup, including spurious readiness. Cancellation
// interrupts the poller even when the context also has a later deadline.
func connectIndexed(ctx context.Context, file *os.File, remote *unix.SockaddrInet6) (result error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err = file.SetWriteDeadline(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = file.SetWriteDeadline(time.Unix(0, 1))
		close(done)
	})
	defer func() {
		if !stop() {
			<-done
		}
		result = errors.Join(result, ctx.Err())
	}()
	var connect error
	started := false
	err = raw.Write(func(fd uintptr) bool {
		if !started {
			started = true
			connect = unix.Connect(int(fd), remote)
		} else {
			var code int
			code, connect = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ERROR)
			if connect == nil && code != 0 {
				connect = unix.Errno(code)
			}
			if connect == nil {
				_, connect = unix.Getpeername(int(fd))
				if connect == unix.ENOTCONN {
					return false
				}
			}
		}
		if connect == unix.EISCONN {
			connect = nil
		}
		return connect != unix.EINPROGRESS && connect != unix.EALREADY && connect != unix.EINTR && connect != unix.EAGAIN
	})
	return errors.Join(err, os.NewSyscallError("connect", connect))
}

func dialIndexedIPv6(ctx context.Context, local, remote netip.AddrPort, index uint32, kind int, transparent bool) (conn net.Conn, result error) {
	sa, err := indexedSockaddr(remote, index)
	if err != nil {
		return nil, err
	}
	file, err := indexedSocket(local, index, kind, transparent)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, cleanupError("dial socket handoff close", file.Close())) }()
	if err = connectIndexed(ctx, file, sa); err != nil {
		return nil, err
	}
	// Conversion only reads numeric addresses for display. Future TCP I/O and
	// connected UDP writes use the connected socket, not those display zones.
	return net.FileConn(file)
}

func listenIndexedIPv6(local netip.AddrPort, index uint32) (packet net.PacketConn, result error) {
	file, err := indexedSocket(local, index, unix.SOCK_DGRAM, false)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, cleanupError("packet socket handoff close", file.Close())) }()
	return net.FilePacketConn(file)
}

func (b *kernelBackend) dialUDP(ctx context.Context, local, remote netip.AddrPort) (conn net.Conn, result error) {
	if local.Addr().IsLinkLocalUnicast() || remote.Addr().IsLinkLocalUnicast() {
		result = b.withIPv6Scope(ctx, func(index uint32) error {
			var err error
			conn, err = dialIndexedIPv6(ctx, local, remote, index, unix.SOCK_DGRAM, true)
			return err
		})
	} else {
		result = namespaceRun(ctx, b.ns, func() error {
			var err error
			conn, err = (&net.Dialer{LocalAddr: net.UDPAddrFromAddrPort(local), Control: socketOptions(true, false)}).DialContext(ctx, family("udp", local.Addr()), remote.String())
			return err
		})
	}
	return conn, result
}
