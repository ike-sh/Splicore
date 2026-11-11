package nativetun

import (
	"context"
	"net"
	"net/netip"
)

type dialBackend interface {
	dialTCP(context.Context, netip.Addr, netip.AddrPort) (net.Conn, error)
	listenUDP(context.Context, netip.Addr) (net.PacketConn, error)
}

// DialTCP shares the ingress stack and its endpoint-owned close barrier.
func (r *Runtime) DialTCP(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	r.mu.Lock()
	b, ok := r.backend.(dialBackend)
	running := r.state == Running
	r.mu.Unlock()
	if !ok || !running {
		return nil, ErrUnavailable
	}
	return b.dialTCP(ctx, local, remote)
}

func (r *Runtime) ListenUDP(ctx context.Context, local netip.Addr) (net.PacketConn, error) {
	r.mu.Lock()
	b, ok := r.backend.(dialBackend)
	running := r.state == Running
	r.mu.Unlock()
	if !ok || !running {
		return nil, ErrUnavailable
	}
	return b.listenUDP(ctx, local)
}
