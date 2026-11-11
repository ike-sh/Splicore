//go:build linux

package wireguardendpoint

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// Interface identity is namespace-local. Never pass a zone string through
// Go's process-wide name cache to select a private WireGuard interface.
// scopeMu keeps the checked link and namespace alive until the operation joins.
func (b *kernelBackend) withIPv6Scope(ctx context.Context, fn func(uint32) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.scopeMu.RLock()
	defer b.scopeMu.RUnlock()
	if b.links == nil || b.ns < 0 || b.meta.InterfaceIndex <= 0 {
		return &BackendError{Class: RuntimeFailure, Operation: "inner link-local interface unavailable", Cause: unix.ENODEV}
	}
	link, err := b.ownedLink(b.links)
	if err != nil {
		return kernelError("inner link-local ownership", RuntimeFailure, err)
	}
	if link.Attrs().Index != b.meta.InterfaceIndex {
		return &BackendError{Class: RuntimeFailure, Operation: "inner link-local interface identity changed", Cause: unix.ENODEV}
	}
	return namespaceRun(ctx, b.ns, func() error { return fn(uint32(link.Attrs().Index)) })
}

// x/sys encodes port byte order and the native sockaddr layout. Only link-local
// unicast needs a scope in Core's supported inner unicast addressing model.
func indexedSockaddr(ap netip.AddrPort, index uint32) (*unix.SockaddrInet6, error) {
	ip := ap.Addr()
	if !ip.Is6() || ip.Is4In6() {
		return nil, &BackendError{Class: ConfigInvalid, Operation: "inner IPv6 socket address"}
	}
	sa := &unix.SockaddrInet6{Addr: ip.As16(), Port: int(ap.Port())}
	if ip.IsLinkLocalUnicast() {
		if index == 0 {
			return nil, &BackendError{Class: RuntimeFailure, Operation: "inner link-local interface scope unavailable", Cause: unix.ENODEV}
		}
		sa.ZoneId = index
	}
	return sa, nil
}

func unscopedEndpoint(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().WithZone(""), ap.Port())
}

// Readback zones are presentation only. Every outgoing scoped destination is
// encoded afresh from verified runtime ownership, never from a received Zone.
type scopedPacket struct {
	net.PacketConn
	backend *kernelBackend
}

func (p *scopedPacket) WriteTo(data []byte, address net.Addr) (int, error) {
	a, ok := address.(*net.UDPAddr)
	if !ok || a == nil {
		return 0, &BackendError{Class: ConfigInvalid, Operation: "inner UDP address"}
	}
	if !a.AddrPort().Addr().IsLinkLocalUnicast() {
		return p.PacketConn.WriteTo(data, address)
	}
	var n int
	err := p.backend.withIPv6Scope(p.backend.e.ctx, func(index uint32) error {
		sa, err := indexedSockaddr(a.AddrPort(), index)
		if err != nil {
			return err
		}
		c, ok := p.PacketConn.(syscall.Conn)
		if !ok {
			return &BackendError{Class: RuntimeFailure, Operation: "inner UDP raw connection unavailable"}
		}
		raw, err := c.SyscallConn()
		if err != nil {
			return err
		}
		n, err = writeRawDatagram(raw, func(fd uintptr) (int, error) {
			return unix.SendmsgN(int(fd), data, nil, sa, 0)
		})
		return err
	})
	if err != nil {
		return n, &net.OpError{Op: "write", Net: "udp6", Source: p.LocalAddr(), Addr: address, Err: &scopeIOError{kernelError("namespace UDP send", RuntimeFailure, err)}}
	}
	return n, nil
}

// Only backpressure asks RawConn to wait. Finish an interrupted callback and
// immediately reenter Write: Go checks the same absolute deadline and closed FD
// on every retry, without waiting for a new writable edge or recreating a socket.
func writeRawDatagram(raw syscall.RawConn, send func(uintptr) (int, error)) (n int, err error) {
	for {
		var sendErr error
		err = raw.Write(func(fd uintptr) bool {
			n, sendErr = send(fd)
			// EWOULDBLOCK is EAGAIN on Linux. EINTR completes this callback.
			return !errors.Is(sendErr, unix.EAGAIN)
		})
		if err != nil || !errors.Is(sendErr, unix.EINTR) {
			return n, errors.Join(err, sendErr)
		}
	}
}

// Keep PacketConn's net.Error contract while retaining the joined namespace,
// syscall and cleanup causes. The index-native write uses the same Go poller.
type scopeIOError struct{ cause error }

func (e *scopeIOError) Error() string { return e.cause.Error() }
func (e *scopeIOError) Unwrap() error { return e.cause }
func (e *scopeIOError) Timeout() bool {
	var cause interface{ Timeout() bool }
	return errors.As(e.cause, &cause) && cause.Timeout()
}

func (e *scopeIOError) Temporary() bool {
	var cause interface{ Temporary() bool }
	return errors.As(e.cause, &cause) && cause.Temporary()
}

func (p *scopedPacket) ReadFrom(data []byte) (int, net.Addr, error) {
	n, address, err := p.PacketConn.ReadFrom(data)
	if a, ok := address.(*net.UDPAddr); ok && a != nil {
		address = net.UDPAddrFromAddrPort(unscopedEndpoint(a.AddrPort()))
	}
	return n, address, err
}
