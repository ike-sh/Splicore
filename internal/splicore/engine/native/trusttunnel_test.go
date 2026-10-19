package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/session"
)

func TestTrustTunnelNativeOwnershipUDPAndMultiUser(t *testing.T) {
	for _, mode := range []string{"http2", "http3", "auto"} {
		if mode != "http2" && !session.H3Enabled() {
			continue
		}
		t.Run(mode, func(t *testing.T) {
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			target, finished := naiveLifecycleTarget(t)
			udp := trojanUDP(t)
			tcp := netaddrEndpoint(target.Addr())
			settings := testkit.TLS(t)
			runtime.GC()
			fdBefore, _ := os.ReadDir("/proc/self/fd")
			gBefore := runtime.NumGoroutine()
			for cycle := range 5 {
				// Port 443 is validation metadata only. The actual runtime socket is
				// opened exactly once with :0, and its actual address is used by clients.
				in := testfixture.MieruIntentAt(t, module.Carrier(mode), access.Endpoint{Host: "127.0.0.1", Port: 443})
				in.Inbound.Protocol = module.Key()
				in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{Mode: mode, TLS: settings})
				if mode == "auto" {
					listener := in.Inbound.Listeners[0]
					listener.ID, _ = identity.NewID()
					listener.Transport = "udp"
					in.Inbound.Listeners = append(in.Inbound.Listeners, listener)
				}
				prepared, e := (TrustTunnelCompiler{}).Compile(ctx, in)
				if e != nil {
					t.Fatal(e)
				}
				h := prepared.(*trustTunnelHandle)
				h.endpoint.Port = 0
				if cycle%3 == 1 {
					h.endpoint.Host = "::1"
				}
				if e = h.Start(ctx); e != nil {
					h.Close(ctx)
					t.Fatal(e)
				}
				h.Activate()
				for user := range 2 {
					n, c := trojanNode(t, in, settings, user)
					n.Protocol = module.Key()
					n.Transport.Kind = module.Carrier(mode)
					options := module.ClientOptions{Mode: mode}
					if mode == "http3" {
						n.Endpoint = netaddrEndpoint(h.packet.LocalAddr())
					} else {
						n.Endpoint = netaddrEndpoint(h.listener.Addr())
					}
					if mode == "auto" {
						options.Addresses = []string{h.packet.LocalAddr().String(), h.listener.Addr().String()}
						options.FallbackDelay = "5ms"
					}
					if cycle%3 == 2 && mode != "auto" {
						n.Endpoint.Host = "LOCALHOST"
					}
					n.Options.Data, _ = json.Marshal(options)
					dialer, e := (TrustTunnelOutboundFactory{}).Build(ctx, n, c)
					if e != nil {
						h.Close(ctx)
						t.Fatal(e)
					}
					conn, e := dialer.DialContext(ctx, tcp)
					if e != nil {
						dialer.Close()
						h.Close(ctx)
						t.Fatal(e)
					}
					_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := []byte("native authenticated TCP")
					if _, e = conn.Write(payload); e != nil {
						t.Fatal(e)
					}
					b := make([]byte, len(payload))
					if _, e = io.ReadFull(conn, b); e != nil || !bytes.Equal(payload, b) {
						t.Fatal(e)
					}
					conn.Close()
					<-finished
					udp.Host = "localhost"
					packet, e := dialer.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
					if e != nil {
						dialer.Close()
						h.Close(ctx)
						t.Fatal(e)
					}
					_ = packet.SetDeadline(time.Now().Add(5 * time.Second))
					for _, size := range []int{0, 1, 1472, 4048} {
						payload := bytes.Repeat([]byte{0x42}, size)
						if _, e = packet.WriteTo(payload, netaddr.UDP(udp)); e != nil {
							t.Fatal(e)
						}
						buffer := make([]byte, 65535)
						count, _, e := packet.ReadFrom(buffer)
						if e != nil || !bytes.Equal(payload, buffer[:count]) {
							t.Fatal(size, e)
						}
					}
					packet.Close()
					dialer.Close()
					if h.BindingStats(in.Bindings[user].ID).Upload == 0 || h.BindingStats(in.Bindings[user].ID).Download == 0 {
						t.Fatal("missing binding attribution")
					}
				}
				closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				e = h.Close(closeCtx)
				cancel()
				if e != nil {
					t.Fatal(e)
				}
				if h.Stats().Active != 0 {
					t.Fatal("sessions retained", h.Stats())
				}
			}
			runtime.GC()
			deadline := time.Now().Add(time.Second)
			for {
				after, _ := os.ReadDir("/proc/self/fd")
				g := runtime.NumGoroutine()
				if len(after) <= len(fdBefore) && g <= gBefore+2 {
					t.Logf("5 cycles goroutines %d->%d fd %d->%d", gBefore, g, len(fdBefore), len(after))
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("resource growth g %d->%d fd %d->%d", gBefore, g, len(fdBefore), len(after))
				}
				runtime.Gosched()
			}
		})
	}
}
func TestTrustTunnelCustomSNIPreservesVerificationIdentity(t *testing.T) {
	settings := testkit.TLS(t)
	tc, e := clientconfig.TLS(access.ClientTLS{Enabled: true, ServerName: settings.ServerName, Trust: "explicit_ca", CACertificate: settings.CACertificate}, settings.ServerName)
	if e != nil {
		t.Fatal(e)
	}
	configureTrustTunnelTLS(tc, module.ClientOptions{CustomSNI: "cover.example.test"})
	if tc.ServerName != "cover.example.test" || tc.VerifyConnection == nil {
		t.Fatal("SNI/verification conflated")
	}
	b, _ := os.ReadFile(settings.CertificateFile)
	pairKey, _ := os.ReadFile(settings.PrivateKeyFile)
	pair, e := tls.X509KeyPair(b, pairKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	certificate := []*x509.Certificate{leaf}
	if e != nil {
		t.Fatal(e)
	}
	if e = tc.VerifyConnection(tls.ConnectionState{PeerCertificates: certificate}); e != nil {
		t.Fatal(e)
	}
	wrong := tc.Clone()
	wrong.RootCAs = nil
	configureTrustTunnelTLS(wrong, module.ClientOptions{CustomSNI: "cover.example.test"})
	if e = wrong.VerifyConnection(tls.ConnectionState{PeerCertificates: certificate}); e == nil {
		t.Fatal("untrusted leaf accepted")
	}
}
