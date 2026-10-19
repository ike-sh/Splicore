//go:build !with_quic

package session

import (
	"context"
	"net"
	"net/http"
	"time"
)

func H3Enabled() bool                 { return false }
func classifyH3(c Code, _ error) Code { return c }
func newH3(context.Context, context.Context, ClientConfig, string) (connection, error) {
	return nil, failure(Config, nil)
}

type h3Server struct{}

func newH3Server(ServerConfig, http.Handler, func(context.Context, func()) context.Context) *h3Server {
	return &h3Server{}
}
func (*h3Server) serve(net.PacketConn) error { return failure(Config, nil) }
func (*h3Server) close() error               { return nil }
func takeH3(http.ResponseWriter, *http.Request, time.Duration, context.CancelFunc) (net.Conn, bool) {
	return nil, false
}
