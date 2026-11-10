//go:build !windows

package transport

import (
	"context"
	"net"
)

func dialControl(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
