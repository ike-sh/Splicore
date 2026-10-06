//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	v "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func expansionRealityTarget(t *testing.T) access.Endpoint {
	t.Helper()
	material := testkit.TLSForName(t, "target.synthetic.test")
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			connections[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
				mu.Lock()
				delete(connections, c)
				mu.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for c := range connections {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}

func TestNativeVLESSSecurityAndSharedNode(t *testing.T) {
	for _, security := range []v.Security{v.Plain, v.TLS, v.Reality} {
		for _, serverEngine := range []string{"native"} {
			t.Run(string(security)+"-server-"+serverEngine, func(t *testing.T) {
				root := t.TempDir()
				s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
					return registry.NativeCore()
				})
				defer stop(t, s, store)
				factories, err := registry.NewOutbounds(native.VLESSOutboundFactory{})
				if err != nil {
					t.Fatal(err)
				}
				if err = s.EnableClientRuntime(context.Background(), factories); err != nil {
					t.Fatal(err)
				}
				settings := v.Settings{Security: security, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}
				public := ""
				private := ""
				clientSecurity := client.Security{Kind: string(security)}
				if security == v.TLS {
					material := testkit.TLS(t)
					settings.TLS = &material
					clientSecurity.TLS = access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}
				}
				if security == v.Reality {
					key, pub, err := v.GenerateServerKey()
					if err != nil {
						t.Fatal(err)
					}
					private = key.Material.Reveal()
					public = string(pub)
					settings.Reality = &v.RealitySettings{PublicKey: pub, ServerName: "target.synthetic.test", Target: expansionRealityTarget(t), ShortIDs: []v.ShortID{"abcd"}}
					clientSecurity.TLS = access.ClientTLS{Enabled: true, ServerName: "target.synthetic.test", Trust: "reality", RealityPublicKey: public, RealityShortID: "abcd"}
				}
				remote := freePort(t)
				document := vlessDoc(t, remote, settings, private)
				var draft map[string]any
				_ = json.Unmarshal(document, &draft)
				draft["engine"] = serverEngine
				alice, _ := identity.NewID()
				bob, _ := identity.NewID()
				draft["users"] = []any{map[string]any{"account_name": "Alice", "uuid": string(alice)}, map[string]any{"account_name": "Bob", "uuid": string(bob)}}
				document, _ = json.Marshal(draft)
				plan, err := s.PlanCreation(context.Background(), "vless", document)
				if err != nil {
					t.Fatal(err)
				}
				created, err := s.ApplyCreation(context.Background(), "vless", application.ApplyRequest{Document: document, Digest: plan.Digest, Revision: plan.Revision})
				if err != nil {
					t.Fatal(err)
				}
				options, _ := json.Marshal(v.ClientOptions{Security: security, Flow: v.NoFlow, PacketEncoding: "xudp"})
				c := expansionCase{name: "vless", key: v.Key(security), transport: "tcp", security: clientSecurity, options: options}
				node := expansionNode(t, s, c, access.Endpoint{Host: "localhost", Port: remote}, expansionCredential(t, store, created, 0))
				nativeOut := expansionProxy(t, s, node, "native")
				sharedOut := expansionProxy(t, s, node, "native")
				localNative := freePort(t)
				localShared := freePort(t)
				addLocal(t, s, localNative, nativeOut)
				localID := addLocal(t, s, localShared, sharedOut)
				tcp4 := echoTarget(t, "127.0.0.1")
				tcp6 := echoTarget(t, "::1")
				tcpDomain := tcp4
				tcpDomain.Host = "localhost"
				udp4 := expansionUDP(t, "127.0.0.1")
				_ = expansionUDP(t, "::1", udp4.Port)
				udp6 := expansionUDP(t, "::1")
				udpDomain := udp4
				udpDomain.Host = "localhost"
				for _, port := range []uint16{localNative, localShared} {
					for _, dst := range []access.Endpoint{tcp4, tcp6, tcpDomain} {
						if err = transfer(port, dst, []byte("shared-node-TCP")); err != nil {
							t.Fatal("TCP", "native client", port == localNative, port, dst, err)
						}
					}
					for _, dst := range []access.Endpoint{udp4, udp6, udpDomain} {
						if err = expansionUDPTraffic(port, dst, []byte("shared-node-UDP")); err != nil {
							t.Fatal("UDP", port, dst, err)
						}
					}
					if err = transfer(port, tcp4, bytes.Repeat([]byte("0123456789abcdef"), 4*1024*1024/16)); err != nil {
						t.Fatal("4 MiB", err)
					}
				}
				waitIdle(t, s)
				// Two native outbounds consume one canonical node; every remote-field mutation
				// must be rejected by actual traffic and recover on the next lease.
				current, _ := s.ClientStatus(context.Background())
				var original client.RemoteNode
				for _, n := range current.State.Nodes {
					if n.ID == node {
						original = n
					}
				}
				if security == v.TLS {
					bad := original
					bad.Security.TLS.CACertificate = testkit.TLS(t).CACertificate
					clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &bad})
					for _, port := range []uint16{localNative, localShared} {
						if expansionBoundedTCP(port, tcp4, []byte("reject-wrong-CA")) == nil {
							t.Fatal("untrusted TLS CA accepted")
						}
					}
					clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &original})
					for _, port := range []uint16{localNative, localShared} {
						if err = expansionBoundedTCP(port, tcp4, []byte("recovered-trust")); err != nil {
							t.Fatal(err)
						}
					}
				}
				if security == v.Reality {
					_, wrongPublic, e := v.GenerateServerKey()
					if e != nil {
						t.Fatal(e)
					}
					for _, field := range []string{"public-key", "short-id", "server-name"} {
						bad := original
						switch field {
						case "public-key":
							bad.Security.TLS.RealityPublicKey = string(wrongPublic)
						case "short-id":
							bad.Security.TLS.RealityShortID = "dcba"
						case "server-name":
							bad.Security.TLS.ServerName = "wrong.synthetic.test"
						}
						clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &bad})
						for _, port := range []uint16{localNative, localShared} {
							if expansionBoundedTCP(port, tcp4, []byte("reject-"+field)) == nil {
								t.Fatal("REALITY field accepted", field)
							}
						}
						clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &original})
						for _, port := range []uint16{localNative, localShared} {
							if err = expansionBoundedTCP(port, tcp4, []byte("recovered-"+field)); err != nil {
								t.Fatal(field, err)
							}
						}
					}
				}
				wrong := wrongInput(expansionCredential(t, store, created, 0))
				clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &wrong})
				for _, port := range []uint16{localNative, localShared} {
					if expansionBoundedTCP(port, tcp4, []byte("wrong-UUID")) == nil {
						t.Fatal("wrong UUID accepted")
					}
				}
				rotation := payloadInput(expansionCredential(t, store, created, 1))
				clientApply(t, s, application.ClientMutation{Resource: "node", Action: "rotate", ID: node, Credential: &rotation})
				for _, port := range []uint16{localNative, localShared} {
					var wg sync.WaitGroup
					fail := make(chan error, 32)
					for range 16 {
						wg.Add(2)
						go func() { defer wg.Done(); fail <- expansionBoundedTCP(port, tcp4, []byte("rotated-mixed-TCP")) }()
						go func() { defer wg.Done(); fail <- expansionUDPTraffic(port, udp4, []byte("rotated-mixed-UDP")) }()
					}
					wg.Wait()
					close(fail)
					for e := range fail {
						if e != nil {
							t.Fatal(e)
						}
					}
				}
				waitIdle(t, s)
				// Delete one client role through the normal reference rules. The same Engine
				// still owns a healthy server role and the other native outbound.
				clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: localID})
				clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "delete", ID: sharedOut})
				if err = transfer(localNative, tcp4, []byte("unrelated-role-survives")); err != nil {
					t.Fatal(err)
				}
				st, _ := s.ClientStatus(context.Background())
				for _, n := range st.State.Nodes {
					if n.ID == node {
						n.Options.Data = []byte(`{"security":"none","flow":"xtls-rprx-vision","packet_encoding":"xudp"}`)
						d, _ := json.Marshal(application.ClientMutation{Resource: "node", Action: "update", ID: node, Node: &n})
						var typed *identity.Error
						if _, err = s.PlanClient(context.Background(), d); !errors.As(err, &typed) || typed.Code != identity.NotImplemented {
							t.Fatal("Vision must reject", err)
						}
					}
				}
			})
		}
	}
}

func TestNativeVLESSIPv6OutboundLifecycle(t *testing.T) {
	root := t.TempDir()
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
		return registry.NativeCore()
	})
	defer stop(t, s, store)
	r, _ := registry.NewOutbounds(native.VLESSOutboundFactory{})
	if err := s.EnableClientRuntime(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	c := expansionCase{name: "vless", key: v.Key(v.Plain), settings: v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, options: []byte(`{"security":"none","flow":"none","packet_encoding":"xudp"}`), transport: "tcp", security: client.Security{Kind: "none"}}
	remote := freePort(t)
	created := expansionCreation(t, s, c, "::1", remote)
	node := expansionNode(t, s, c, access.Endpoint{Host: "::1", Port: remote}, expansionCredential(t, store, created, 0))
	out := expansionProxy(t, s, node, "native")
	port := freePort(t)
	local := addLocal(t, s, port, out)
	tcp := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	if err := transfer(port, tcp, []byte("native-lifecycle")); err != nil {
		t.Fatal(err)
	}
	if err := expansionUDPTraffic(port, udp, []byte("native-lifecycle")); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, s)
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: local})
	clientApply(t, s, application.ClientMutation{Resource: "outbound", Action: "delete", ID: out})
	if _, err := os.Stat(filepath.Join(root, "runtime")); !os.IsNotExist(err) {
		t.Fatal("unexpected external runtime artifacts", err)
	}
}
