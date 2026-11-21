package ports

import (
	"context"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
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

// WithDirectServerTarget restricts a scoped route to the native ServerTarget
// dialer and checks the logical target after Core DNS.
func WithDirectServerTarget(ctx context.Context, check func(access.Endpoint) error) context.Context {
	return context.WithValue(ctx, directServerTargetKey{}, check)
}

type directServerTargetKey struct{}

func DirectServerTargetCheck(ctx context.Context) func(access.Endpoint) error {
	check, _ := ctx.Value(directServerTargetKey{}).(func(access.Endpoint) error)
	return check
}
