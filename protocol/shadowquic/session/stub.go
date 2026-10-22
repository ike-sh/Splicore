//go:build !with_quic

package session

import (
	"context"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func Enabled() bool { return false }

type (
	Client struct{}
	Server struct{}
)

func NewClient(ClientConfig) (*Client, error) { return nil, ErrUnavailable }

func (*Client) Open(context.Context, access.Endpoint) (net.Conn, error) { return nil, ErrUnavailable }

func (*Client) OpenPacket(context.Context, access.Endpoint) (net.PacketConn, error) {
	return nil, ErrUnavailable
}
func (*Client) Close() error { return nil }
func NewServer(context.Context, net.PacketConn, ServerConfig) (*Server, error) {
	return nil, ErrUnavailable
}
func (*Server) Close(context.Context) error { return nil }
