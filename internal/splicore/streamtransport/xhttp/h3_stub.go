//go:build !with_quic

package xhttp

import (
	"crypto/tls"
	"net"
	"net/http"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

const h3Compiled = false

func newH3Transport(Security, int64) http.RoundTripper { return nil }

func NewPacketListener(net.PacketConn, cfg.Config, *tls.Config) (net.Listener, error) {
	return nil, errEnvelope
}
