//go:build !with_utls

package backend

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"net"
)

func RealityServer(string, string, []string, access.Endpoint, func(context.Context, string, string) (net.Conn, error)) (func(context.Context, net.Conn) (net.Conn, error), error) {
	return nil, errors.New("REALITY requires with_utls")
}
func RealityServerNames([]string, string, []string, access.Endpoint, func(context.Context, string, string) (net.Conn, error)) (func(context.Context, net.Conn) (net.Conn, error), error) {
	return nil, errors.New("REALITY requires with_utls")
}
func RealityClient(context.Context, net.Conn, access.ClientTLS) (net.Conn, error) {
	return nil, errors.New("REALITY requires with_utls")
}
