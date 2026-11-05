//go:build linux

package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

func TestTrustTunnelCustomSNIActualHandshake(t *testing.T) {
	for _, mode := range []string{"http2", "http3"} {
		if mode == "http3" && !session.H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			settings := testkit.TLS(t)
			cert, _ := os.ReadFile(settings.CertificateFile)
			key, _ := os.ReadFile(settings.PrivateKeyFile)
			pair, e := tls.X509KeyPair(cert, key)
			if e != nil {
				t.Fatal(e)
			}
			hello := make(chan string, 1)
			server, e := session.NewServer(session.ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				select {
				case hello <- h.ServerName:
				default:
				}
				return nil, nil
			}}, HTTP2: mode == "http2", HTTP3: mode == "http3", Authenticate: func(u, p string) (string, bool) { return u, u == "alpha" && p == "synthetic" }, DialTCP: func(ctx context.Context, _, a string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", a)
			}, DialUDP: func(ctx context.Context, _, a string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", a)
			}, Relay: func(ctx context.Context, _ string, a, b net.Conn) { relay.Join(ctx, a, b) }})
			if e != nil {
				t.Fatal(e)
			}
			var address string
			done := make(chan struct{})
			if mode == "http2" {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				address = l.Addr().String()
				go func() { defer close(done); server.ServeTCP(l) }()
			} else {
				p, e := net.ListenPacket("udp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer p.Close()
				address = p.LocalAddr().String()
				go func() { defer close(done); server.ServeUDP(p) }()
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if e := server.Close(ctx); e != nil {
					t.Error(e)
				}
				<-done
			}()
			tc, e := clientconfig.TLS(access.ClientTLS{Enabled: true, ServerName: settings.ServerName, Trust: "explicit_ca", CACertificate: settings.CACertificate}, settings.ServerName)
			if e != nil {
				t.Fatal(e)
			}
			configureTrustTunnelTLS(tc, module.ClientOptions{CustomSNI: "cover.example.test"})
			c, e := session.NewClient(session.ClientConfig{Mode: mode, Addresses: []string{address}, TLS: tc, Username: "alpha", Password: "synthetic", DialTCP: (&net.Dialer{}).DialContext, PacketSocket: func(ctx context.Context, a string) (net.PacketConn, net.Addr, error) {
				remote, e := net.ResolveUDPAddr("udp", a)
				if e != nil {
					return nil, nil, e
				}
				p, e := net.ListenPacket("udp4", "127.0.0.1:0")
				return p, remote, e
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			if e := c.Check(context.Background()); e != nil {
				t.Fatal(e)
			}
			select {
			case sni := <-hello:
				if sni != "cover.example.test" {
					t.Fatal(sni)
				}
			case <-time.After(time.Second):
				t.Fatal("SNI not observed")
			}
		})
	}
}

func TestTrustTunnelTargetsUseCoreUnderlayPolicy(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "::ffff:127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			backend := &trustTunnelDenyBackend{}
			factory := underlay.NewWithBackend(backend)
			ctx := underlay.WithFactory(context.Background(), factory)
			lease, e := factory.Begin(ctx, true)
			if e != nil {
				t.Fatal(e)
			}
			defer lease.Close()
			settings := testkit.TLS(t)
			in := testfixture.MieruIntentAt(t, "tcp", access.Endpoint{Host: "127.0.0.1", Port: 443})
			in.Inbound.Protocol = module.Key()
			in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{Mode: "http2", TLS: settings})
			prepared, e := (TrustTunnelCompiler{}).Compile(ctx, in)
			if e != nil {
				t.Fatal(e)
			}
			h := prepared.(*trustTunnelHandle)
			h.endpoint.Port = 0
			if e = h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			defer h.Close(ctx)
			n, c := trojanNode(t, in, settings, 0)
			n.Protocol = module.Key()
			n.Endpoint = netaddrEndpoint(h.listener.Addr())
			n.Options.Data = []byte(`{"mode":"http2"}`)
			d, e := (TrustTunnelOutboundFactory{}).Build(ctx, n, c)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			if conn, e := d.DialContext(ctx, access.Endpoint{Host: host, Port: 443}); e == nil {
				conn.Close()
				t.Fatal("host policy bypass", host)
			}
			if backend.attempts.Load() < 1 {
				t.Fatal("targets did not reach Core socket owner", backend.attempts.Load())
			}
		})
	}
}

func TestTrustTunnelRawEchoNamespace(t *testing.T) {
	if os.Getenv("SPLICORE_TRUSTTUNNEL_RAW_ICMP") != "1" {
		t.Skip("explicit isolated raw-socket qualification required")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	d, e := underlay.DialerFrom(ctx, underlay.ServerTarget)
	if e != nil {
		t.Fatal(e)
	}
	echo := trustTunnelEcho(d)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		for _, ttl := range []uint8{32, 64} {
			for _, size := range []uint16{0, 32} {
				r := wire.EchoRequest{ID: 57, Sequence: uint16(ttl), Destination: netip.MustParseAddr(ip), TTL: ttl, DataSize: size}
				request, cancel := context.WithTimeout(ctx, time.Second)
				reply, e := echo(request, "synthetic", r)
				cancel()
				if e != nil || reply.ID != r.ID || reply.Sequence != r.Sequence || reply.Source != r.Destination {
					t.Fatal(ip, ttl, size, e)
				}
			}
		}
	}
	t.Log("8 isolated native raw ICMP echo checks; official client direction NOT QUALIFIED")
}

func TestTrustTunnelDiagnosticSecretsRedacted(t *testing.T) {
	secret := "synthetic-must-never-appear"
	_, e := module.DecodeClient([]byte(`{"mode":"http2","user_agent":"` + secret + `\r\n"}`))
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("config secret in error", e)
	}
}
