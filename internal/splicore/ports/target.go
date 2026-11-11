package ports

import (
	"context"
	"net"
)

// TargetDialer is a protocol-independent Core flow routing boundary. It is
// distinct from underlay socket protection and handshake infrastructure I/O.
type TargetDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}
type (
	targetKey      struct{}
	TargetRouter   func(context.Context, string, string, TargetDialer) (net.Conn, error)
	TargetDialFunc func(context.Context, string, string) (net.Conn, error)
)

func (f TargetDialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func WithTargetRouter(ctx context.Context, router TargetRouter) context.Context {
	return context.WithValue(ctx, targetKey{}, router)
}

func RoutedTargetDialer(ctx context.Context, fallback TargetDialer) TargetDialer {
	if router, ok := ctx.Value(targetKey{}).(TargetRouter); ok {
		return TargetDialFunc(func(call context.Context, network, address string) (net.Conn, error) {
			return router(call, network, address, fallback)
		})
	}
	return fallback
}
