//go:build !with_quic

package streamtransport

import (
	"context"
	"crypto/tls"
	"net"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type PacketSocket func(context.Context) (net.PacketConn, net.Addr, error)

func NewPacketClient(PacketSocket, cfg.Config, *tls.Config) (*Client, error) {
	return nil, errNativeConfig
}

func newQUICListener(net.PacketConn, cfg.Config, *tls.Config) (net.Listener, error) {
	return nil, errNativeConfig
}
