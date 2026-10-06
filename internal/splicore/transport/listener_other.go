//go:build !linux

package transport

import (
	"context"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func Listen(string) (net.Listener, error) {
	return nil, identity.Err(identity.NotImplemented, "production control transport requires Linux; use httptest for Windows development")
}
func ConnContext(ctx context.Context, _ net.Conn) context.Context { return ctx }
func ProductionSupported() bool                                   { return false }
