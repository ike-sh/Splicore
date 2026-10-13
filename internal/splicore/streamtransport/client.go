package streamtransport

import (
	"context"
	"crypto/tls"
	"net"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/xhttp"
)

// Client owns reusable HTTP transport resources for one configured outbound.
// Protocol framing stays above this interface and approved sockets stay below.
type Client struct{ impl *xhttp.Client }
type ClientSecurity = xhttp.Security
type SecurityResolver = xhttp.Resolver

func NewClient(dial DialFunc, target string, c cfg.Config, security ClientSecurity, resolve SecurityResolver) (*Client, error) {
	impl, e := xhttp.NewClient(xhttp.DialFunc(dial), target, c, security, resolve)
	if e != nil {
		return nil, e
	}
	return &Client{impl: impl}, nil
}
func (c *Client) DialContext(ctx context.Context) (net.Conn, error) { return c.impl.DialContext(ctx) }
func (c *Client) Close() error                                      { return c.impl.Close() }

// WrapSecureListener composes an existing nonstandard security handshake below
// the shared HTTP transport. The handshake itself belongs to its security layer.
func WrapSecureListener(base net.Listener, c cfg.Config, handshake func(context.Context, net.Conn) (net.Conn, error)) (net.Listener, error) {
	return xhttp.NewListener(base, c, nil, handshake)
}
func dialXHTTP(ctx context.Context, dial DialFunc, target string, c cfg.Config, tc *tls.Config) (net.Conn, error) {
	client, e := NewClient(dial, target, c, ClientSecurity{TLS: tc}, nil)
	if e != nil {
		return nil, e
	}
	conn, e := client.DialContext(ctx)
	if e != nil {
		client.Close()
		return nil, e
	}
	return &singleClientConn{Conn: conn, client: client}, nil
}

type singleClientConn struct {
	net.Conn
	client *Client
}

func (c *singleClientConn) Close() error { c.Conn.Close(); return c.client.Close() }
