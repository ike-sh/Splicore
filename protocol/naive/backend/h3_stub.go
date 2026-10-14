//go:build !with_quic

package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"
)

func H3Enabled() bool { return false }

func h3TunnelContext(req *http.Request) context.Context { return req.Context() }
func newH3Connection(context.Context, context.Context, ClientConfig) (connection, error) {
	return nil, errors.New("Naive HTTP/3 requires with_quic")
}

type disabledH3 struct{}

func newH3Server(*tls.Config, http.Handler, int, time.Duration) http3Server { return disabledH3{} }
func (disabledH3) serve(net.PacketConn) error                               { return errors.New("Naive HTTP/3 requires with_quic") }
func (disabledH3) close() error                                             { return nil }
func takeH3Stream(http.ResponseWriter, *http.Request, time.Duration, context.CancelFunc) (net.Conn, bool) {
	return nil, false
}
