package native

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	shared "github.com/ike-sh/Splicore/internal/splicore/streamtransport"
	"github.com/ike-sh/Splicore/protocol/vless/backend"
)

func sharedSecurity(kind string, t access.ClientTLS, tc *tls.Config) (shared.ClientSecurity, error) {
	s := shared.ClientSecurity{TLS: tc, ServerName: t.ServerName, Reality: kind == "reality"}
	if kind == "reality" {
		s.Handshake = func(ctx context.Context, c net.Conn) (net.Conn, error) { return backend.RealityClient(ctx, c, t) }
	}
	return s, nil
}

func sharedClient(ctx context.Context, dial shared.DialFunc, n client.RemoteNode, tc *tls.Config) (*shared.Client, error) {
	if n.Transport.Type() == "quic-stream" {
		socket, err := nativePacketSocket(ctx, n.Endpoint)
		if err != nil {
			return nil, err
		}
		return shared.NewPacketClient(socket, n.Transport, tc)
	}
	if n.Transport.Type() != "xhttp" && !n.Transport.NativeStream() {
		return nil, nil
	}
	if n.Transport.NativeStream() {
		dial = nativeManagedDial(ctx, dial)
	}
	s, e := sharedSecurity(n.Security.Kind, n.Security.TLS, tc)
	if e != nil {
		return nil, e
	}
	if n.Transport.XHTTPH3(n.Security.TLS.ALPN) {
		s.PacketSocket, e = nativePacketSocket(ctx, n.Endpoint)
		if e != nil {
			return nil, e
		}
	}
	resolve := func(d cfg.Download) (shared.ClientSecurity, error) {
		var tc *tls.Config
		if d.Security == "tls" {
			var e error
			tc, e = clientconfig.TLS(d.TLS, d.Endpoint.Host)
			if e != nil {
				return shared.ClientSecurity{}, e
			}
		}
		s, e := sharedSecurity(d.Security, d.TLS, tc)
		if e == nil && d.Transport.XHTTPH3(d.TLS.ALPN) {
			s.PacketSocket, e = nativePacketSocket(ctx, d.Endpoint)
		}
		return s, e
	}
	return shared.NewClient(dial, net.JoinHostPort(n.Endpoint.Host, portString(n.Endpoint.Port)), n.Transport, s, resolve)
}

func transportALPN(tc *tls.Config) []string {
	if tc == nil {
		return nil
	}
	return tc.NextProtos
}
