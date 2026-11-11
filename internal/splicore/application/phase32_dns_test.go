//go:build with_quic && with_utls

package application_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func TestPhase32ApplicationDNSRoutingSQLite(t *testing.T) {
	for _, protocol := range []string{"vless"} {
		for _, kind := range []string{"http", "h2", "quic-stream"} {
			t.Run(protocol+"/"+kind, func(t *testing.T) {
				ambient := isolatedResolver(t)
				if ambient == nil {
					return
				}
				ctx := context.Background()
				root := t.TempDir()
				path := filepath.Join(root, "original", "state.db")
				s, store := setupProtocols(t, path, nil, registry.NativeCore)
				closed := false
				defer func() {
					if !closed {
						stop(t, s, store)
					}
				}()
				c := vmessCase(t)
				tr := cfg.Config{Kind: kind, Path: "/phase32", Host: "authority.synthetic.test"}
				if kind == "quic-stream" {
					tr.Path = ""
					tr.Host = ""
				}
				switch protocol {
				case "vmess":
					v := c.settings.(vm.Settings)
					v.Stream = &tr
					c.settings = v
				case "trojan":
					c = trojanCase(t)
					v := c.settings.(tm.Settings)
					v.Stream = &tr
					c.settings = v
				case "vless":
					material := c.settings.(vm.Settings).TLS
					c = expansionCase{"vless", vl.Key(vl.TLS), vl.Settings{Security: vl.TLS, Flow: vl.NoFlow, Transport: "tcp", PacketEncoding: "xudp", TLS: material, Stream: &tr}, []byte(`{"security":"tls","flow":"none","packet_encoding":"xudp"}`), kind, c.security, native.VLESSOutboundFactory{}}
				}
				adapters, e := registry.NewOutbounds(c.factory)
				if e != nil {
					t.Fatal(e)
				}
				if e = s.EnableClientRuntime(ctx, adapters); e != nil {
					t.Fatal(e)
				}
				port := freePort(t)
				if kind == "quic-stream" {
					port = udpPort(t)
				}
				decryption, public, e := encryption.Generate("x25519", "random", "0rtt", "600s", "100-35-35")
				if e != nil {
					t.Fatal(e)
				}
				var document map[string]any
				if e = json.Unmarshal(vlessDoc(t, port, c.settings.(vl.Settings), ""), &document); e != nil {
					t.Fatal(e)
				}
				document["server_secret"] = map[string]any{"decryption": decryption}
				data, _ := json.Marshal(document)
				created := applyVLESS(t, s, data)
				c.options, _ = json.Marshal(vl.ClientOptions{Security: vl.TLS, Flow: vl.NoFlow, PacketEncoding: "xudp", Encryption: public})
				credential := payloadInput(expansionCredential(t, store, created, 0))
				n := client.RemoteNode{Name: "phase32 native node", Protocol: c.key, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: port}, Transport: tr, Security: c.security, Options: client.Options{Schema: 1, Data: c.options}}
				node := clientApply(t, s, application.ClientMutation{Resource: "node", Action: "create", Node: &n, Credential: &credential}).ID
				out := expansionProxy(t, s, node, "native")
				local := freePort(t)
				addLocal(t, s, local, out)
				target := echoTarget(t, "127.0.0.1")
				if e = transfer(local, target, []byte("native composition")); e != nil {
					t.Fatal(e)
				}
				// Existing canonical Core DNS and route policy drive the actual client runtime.
				queries := &atomic.Int64{}
				dns := managedDNSFixture(t, queries)
				resolver := networkID(t)
				config := P.Config{Servers: []P.DNSServer{{ID: resolver, Name: "Phase32 Core DNS", Type: "udp", Endpoint: dns, Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: resolver, BootstrapServer: resolver, Strategy: "ipv4_only", TimeoutSeconds: 2, Cache: P.DNSCachePolicy{Capacity: 4}}, Route: P.RouteProfile{Final: &P.Action{Kind: P.Outbound, ID: out}, Rules: []P.RouteRule{{ID: networkID(t), Name: "reject", Match: P.RuleMatch{Domains: []string{"blocked.test"}}, Action: P.Action{Kind: P.Reject}}, {ID: networkID(t), Name: "direct", Match: P.RuleMatch{Domains: []string{"direct.test"}}, Action: P.Action{Kind: P.Direct}}}}}
				applyNetwork(t, s, config)
				ipv6 := echoTarget(t, "::1")
				if e = transfer(local, ipv6, []byte("encrypted IPv6 route")); e != nil {
					t.Fatal(e)
				}
				status, e := s.ClientStatus(ctx)
				if e != nil {
					t.Fatal(e)
				}
				saved := status.State.Nodes[0]
				saved.Endpoint.Host = "proxy.fixture.local"
				clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: saved.ID, Node: &saved})
				for _, host := range []string{"managed.test", "direct.test"} {
					dst := target
					dst.Host = host
					if e = transfer(local, dst, []byte("managed route")); e != nil {
						t.Fatal(host, e)
					}
				}
				for _, host := range []string{"blocked.test", "missing.fixture.local"} {
					dst := target
					dst.Host = host
					if transfer(local, dst, []byte("must reject")) == nil {
						t.Fatal("route/DNS bypass", host)
					}
				}
				if ambient.Load() != 0 || queries.Load() == 0 {
					t.Fatal("DNS ownership", ambient.Load(), queries.Load())
				}
				// Foreign peer projections must reject rather than publish incompatible wire intent.
				if _, e = s.ExportClient(ctx, created.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.2", BindingID: created.Bindings[0].BindingID}); e == nil {
					t.Fatal("lossy foreign export")
				}
				clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
				clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
				if e = transfer(local, target, []byte("runtime restart")); e != nil {
					t.Fatal(e)
				}
				before, _ := s.ClientStatus(ctx)
				stop(t, s, store)
				closed = true
				s, store = setupProtocols(t, path, nil, registry.NativeCore)
				closed = false
				if e = s.EnableClientRuntime(ctx, adapters); e != nil {
					t.Fatal(e)
				}
				after, _ := s.ClientStatus(ctx)
				if !reflect.DeepEqual(before.State, after.State) {
					t.Fatal("SQLite changed committed transport intent")
				}
				if e = transfer(local, target, []byte("SQLite restart")); e != nil {
					t.Fatal(e)
				}
				stop(t, s, store)
				closed = true
				backup := filepath.Join(root, "backup", "state.db")
				backup = persistedDatabaseFixture(t, ctx, path, backup)
				s, store = setupProtocols(t, backup, nil, registry.NativeCore)
				closed = false
				if e = s.EnableClientRuntime(ctx, adapters); e != nil {
					t.Fatal(e)
				}
				if e = transfer(local, target, []byte("backup restore")); e != nil {
					t.Fatal(e)
				}
				if ambient.Load() != 0 {
					t.Fatal("system DNS fallback", ambient.Load())
				}
			})
		}
	}
}
