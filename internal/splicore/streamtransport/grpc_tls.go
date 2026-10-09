package streamtransport

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// grpcTLSCredentials keeps an explicit shared TLS identity independent of the
// channel's HTTP/2 authority. grpc-go otherwise uses authority both to check
// ProtocolInfo.ServerName and to replace tls.Config.ServerName at handshake.
// The underlying TLS credentials still own certificate verification and ALPN.
type grpcTLSCredentials struct {
	base       credentials.TransportCredentials
	serverName string
}

func (c *grpcTLSCredentials) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	if c.serverName != "" {
		authority = c.serverName
	}
	return c.base.ClientHandshake(ctx, authority, raw)
}

func (c *grpcTLSCredentials) ServerHandshake(raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return c.base.ServerHandshake(raw)
}

func (c *grpcTLSCredentials) Info() credentials.ProtocolInfo {
	i := c.base.Info()
	// This is not a channel authority override. Explicit TLS identity is applied
	// only by ClientHandshake above.
	i.ServerName = ""
	return i
}

func (c *grpcTLSCredentials) Clone() credentials.TransportCredentials {
	return &grpcTLSCredentials{base: c.base.Clone(), serverName: c.serverName}
}

func (c *grpcTLSCredentials) OverrideServerName(name string) error {
	if err := c.base.OverrideServerName(name); err != nil {
		return err
	}
	c.serverName = name
	return nil
}
