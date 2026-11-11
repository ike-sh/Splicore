//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestPhase32PinnedSecurityVisionInterop(t *testing.T) {
	binary := os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE")
	if binary == "" {
		t.Skip("external pinned reference not configured")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	echo := netaddrEndpoint(vlessEcho(t, nil).Addr())
	for _, security := range []vl.Security{vl.Plain, vl.TLS, vl.Reality} {
		for _, flow := range []vl.Flow{vl.NoFlow, vl.Vision} {
			for _, mode := range []string{"native", "xorpub", "random"} {
				for _, direction := range []string{"splicore-client", "splicore-server"} {
					t.Run(string(security)+"/"+string(flow)+"/"+mode+"/"+direction, func(t *testing.T) {
						profile := phaseProfile{security: security, flow: flow}
						in, n, credential := phaseFixture(t, profile)
						public := phase32EnableMode(t, &in, mode)
						options, _ := vl.DecodeClientOptions(n.Options.Data)
						options.Encryption = public
						n.Options.Data, _ = json.Marshal(options)
						socks := access.Endpoint{Host: "127.0.0.1", Port: uint16(testkit.PeerPort(t, "tcp"))}
						var e error
						root := t.TempDir()
						if evidence := os.Getenv("SPLICORE_PHASE32_PEER_LOGS"); evidence != "" {
							root, e = os.MkdirTemp(evidence, testkit.EvidenceName(t.Name())+"-")
							if e != nil {
								t.Fatal(e)
							}
						}
						name := strings.ReplaceAll(t.Name(), "/", "-")
						peer := phasePeerConfig(t, profile, in, n, credential, socks, direction, root, name).(map[string]any)
						if direction == "splicore-client" {
							settings := peer["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
							settings["decryption"] = in.ServerCredentials[len(in.ServerCredentials)-1].Payload.(access.PrivateKeyPayload).Material.Reveal()
						} else {
							settings := peer["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
							settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = public
						}
						var dial func(access.Endpoint) (net.Conn, error)
						peerAddress := n.Endpoint
						if direction == "splicore-server" {
							h := sharedPrepare(t, ctx, "vless", in)
							if e = h.Start(ctx); e != nil {
								t.Fatal(e)
							}
							h.Activate()
							defer h.Close(ctx)
							peerAddress = socks
							dial = func(dst access.Endpoint) (net.Conn, error) { return phaseSOCKS(socks, dst) }
						} else {
							d := sharedBuild(t, ctx, n, credential)
							defer d.Close()
							dial = func(dst access.Endpoint) (net.Conn, error) { return d.DialContext(ctx, dst) }
						}
						phasePeer(t, root, binary, name, peer, peerAddress)
						if security == vl.Reality && direction == "splicore-client" {
							// The pinned reference probes post-handshake target record
							// lengths asynchronously with a five-second timeout.
							// Wait for that startup work before measuring admission.
							time.Sleep(6 * time.Second)
						}
						for range 2 {
							c, e := dial(echo)
							if e != nil {
								t.Fatal(e)
							}
							if e = phaseExchange(c, bytes.Repeat([]byte("security encrypted payload"), 3000)); e != nil {
								c.Close()
								t.Fatal(e)
							}
							c.Close()
						}
						if flow == vl.Vision {
							material := testkit.TLSForName(t, "inner.synthetic.test")
							cert, _ := os.ReadFile(material.CertificateFile)
							key, _ := os.ReadFile(material.PrivateKeyFile)
							pair, e := tls.X509KeyPair(cert, key)
							clear(key)
							if e != nil {
								t.Fatal(e)
							}
							target := netaddrEndpoint(vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}).Addr())
							raw, e := dial(target)
							if e != nil {
								t.Fatal(e)
							}
							inner := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
							defer inner.Close()
							if e = phaseExchange(inner, bytes.Repeat([]byte("actual inner TLS application"), 40000)); e != nil {
								t.Fatal("Vision direct transition", e)
							}
						}
					})
				}
			}
		}
	}
}

func TestPhase32PinnedTransportInterop(t *testing.T) {
	binary := os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE")
	if binary == "" {
		t.Skip("external pinned reference not configured")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	echo := netaddrEndpoint(vlessEcho(t, nil).Addr())
	for _, kind := range []string{"xhttp-h1", "xhttp-h2", "mkcp"} {
		for _, direction := range []string{"splicore-client", "splicore-server"} {
			t.Run(kind+"/"+direction, func(t *testing.T) {
				p := phaseProfile{security: vl.TLS, flow: vl.NoFlow}
				if kind == "mkcp" {
					p.security = vl.Plain
				}
				in, n, cred := phaseFixture(t, p)
				tr := cfg.Config{Kind: "mkcp"}
				alpn := "h2"
				if kind != "mkcp" {
					tr = cfg.Config{Kind: "xhttp", Path: "/phase32", Host: "core.synthetic.test", XHTTP: &cfg.XHTTP{Mode: "packet-up"}}
					if kind == "xhttp-h1" {
						alpn = "http/1.1"
					}
					n.Security.TLS.ALPN = []string{alpn}
				}
				n.Transport = tr
				var settings vl.Settings
				if e := json.Unmarshal(in.Inbound.Settings.Data, &settings); e != nil {
					t.Fatal(e)
				}
				settings.Stream = &tr
				in.Inbound.Settings.Data, _ = json.Marshal(settings)
				for j := range in.Inbound.Listeners {
					in.Inbound.Listeners[j].Transport = tr.Carrier()
				}
				public := phase32Enable(t, &in)
				options, _ := vl.DecodeClientOptions(n.Options.Data)
				options.Encryption = public
				n.Options.Data, _ = json.Marshal(options)
				socks := access.Endpoint{Host: "127.0.0.1", Port: uint16(testkit.PeerPort(t, "tcp"))}
				var e error
				root := t.TempDir()
				if evidence := os.Getenv("SPLICORE_PHASE32_PEER_LOGS"); evidence != "" {
					root, e = os.MkdirTemp(evidence, testkit.EvidenceName(t.Name())+"-")
					if e != nil {
						t.Fatal(e)
					}
				}
				name := strings.ReplaceAll(t.Name(), "/", "-")
				peer := phasePeerConfig(t, p, in, n, cred, socks, direction, root, name).(map[string]any)
				section := "inbounds"
				if direction == "splicore-server" {
					section = "outbounds"
				}
				proxy := peer[section].([]any)[0].(map[string]any)
				stream := proxy["streamSettings"].(map[string]any)
				if kind == "mkcp" {
					stream["network"] = "kcp"
					stream["kcpSettings"] = tr.MKCPSettings()
				} else {
					stream["network"] = "xhttp"
					stream["xhttpSettings"] = map[string]any{"mode": "packet-up", "path": tr.Path, "host": tr.Host}
					stream["tlsSettings"].(map[string]any)["alpn"] = []string{alpn}
					stream["tlsSettings"].(map[string]any)["fingerprint"] = "unsafe"
				}
				ps := proxy["settings"].(map[string]any)
				if direction == "splicore-client" {
					ps["decryption"] = in.ServerCredentials[len(in.ServerCredentials)-1].Payload.(access.PrivateKeyPayload).Material.Reveal()
					// Probe process readiness on a separate TCP listener for UDP transports.
					peer["inbounds"] = append(peer["inbounds"].([]any), map[string]any{"listen": socks.Host, "port": socks.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}})
				} else {
					ps["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = public
				}
				var dial func(access.Endpoint) (net.Conn, error)
				if direction == "splicore-server" {
					h := sharedPrepare(t, ctx, "vless", in)
					if e = h.Start(ctx); e != nil {
						t.Fatal(e)
					}
					h.Activate()
					defer h.Close(ctx)
					dial = func(dst access.Endpoint) (net.Conn, error) { return phaseSOCKS(socks, dst) }
				} else {
					d := sharedBuild(t, ctx, n, cred)
					defer d.Close()
					dial = func(dst access.Endpoint) (net.Conn, error) { return d.DialContext(ctx, dst) }
				}
				phasePeer(t, root, binary, name, peer, socks)
				for range 2 {
					conn, e := dial(echo)
					if e != nil {
						t.Fatal(e)
					}
					e = phaseExchange(conn, bytes.Repeat([]byte("encrypted transport"), 3000))
					conn.Close()
					if e != nil {
						t.Fatal(e)
					}
				}
			})
		}
	}
}
