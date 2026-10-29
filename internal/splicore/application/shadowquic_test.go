//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/cli"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"github.com/miekg/dns"
)

func TestShadowQUICApplicationDNSRoutingRestartAndRestore(t *testing.T) {
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
	adapters, e := registry.NewOutbounds(native.ShadowQUICOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(ctx, adapters); e != nil {
		t.Fatal(e)
	}
	port := udpPort(t)
	settings := module.Settings{ServerName: "cover.test", Camouflage: access.Endpoint{Host: "127.0.0.1", Port: 9}}
	doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "ShadowQUIC lifecycle", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": settings, "users": []any{map[string]any{"account_name": "Display account", "username": "shadow-auth", "password": "synthetic-shadow-secret"}}})
	plan, e := s.PlanCreation(ctx, "shadowquic", doc)
	if e != nil {
		t.Fatal(e)
	}
	created, e := s.ApplyCreation(ctx, "shadowquic", application.ApplyRequest{Document: doc, Digest: plan.Digest, Revision: plan.Revision})
	if e != nil {
		t.Fatal(e)
	}
	c := expansionCase{"shadowquic", module.Key(), settings, []byte(`{"handshake_timeout":1}`), "quic", client.Security{Kind: "jls", TLS: access.ClientTLS{Enabled: true, ServerName: "cover.test", ALPN: []string{"h3"}, Trust: "jls"}}, native.ShadowQUICOutboundFactory{}}
	node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
	out := expansionProxy(t, s, node, "native")
	local := freePort(t)
	addLocal(t, s, local, out)
	target := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	var queries atomic.Int64
	dns := shadowQUICDNS(t, &queries)
	resolver := networkID(t)
	config := P.Config{Servers: []P.DNSServer{{ID: resolver, Name: "controlled Core DNS", Type: "udp", Endpoint: dns, Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: resolver, BootstrapServer: resolver, Strategy: "ipv4_only", TimeoutSeconds: 2, Cache: P.DNSCachePolicy{Capacity: 4}}, Route: P.RouteProfile{Final: &P.Action{Kind: P.Outbound, ID: out}, Rules: []P.RouteRule{{ID: networkID(t), Name: "blocked domain", Match: P.RuleMatch{Domains: []string{"blocked.test"}}, Action: P.Action{Kind: P.Reject}}, {ID: networkID(t), Name: "direct domain", Match: P.RuleMatch{Domains: []string{"direct.test"}}, Action: P.Action{Kind: P.Direct}}}}}
	applyNetwork(t, s, config)
	// Managed resolution must precede adapter construction and must never fall back.
	for _, host := range []string{"managed.test", "127.0.0.1", "::ffff:127.0.0.1", "direct.test"} {
		dst := target
		dst.Host = host
		if e = transfer(local, dst, []byte("managed native ShadowQUIC")); e != nil {
			t.Fatal(host, e)
		}
	}
	domainUDP := udp
	domainUDP.Host = "managed.test"
	if e = expansionUDPTraffic(local, domainUDP, []byte("Core DNS UDP")); e != nil {
		t.Fatal(e)
	}
	blocked := target
	blocked.Host = "blocked.test"
	if transfer(local, blocked, []byte("blocked")) == nil {
		t.Fatal("route reject bypass")
	}
	// The controlled DNS fixture returns NXDOMAIN for this exact name.
	missing := target
	missing.Host = "missing.fixture.local"
	if transfer(local, missing, []byte("nxdomain")) == nil {
		t.Fatal("NXDOMAIN bypass")
	}
	if ambient.Load() != 0 || queries.Load() == 0 {
		t.Fatal("DNS ownership", ambient.Load(), queries.Load())
	}

	// Bypass local-client resolution deliberately: wire domains must be resolved by
	// the server's retained Core DNS generation, never by an ambient target dial.
	state, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	wireNode := state.State.Nodes[0]
	wireCredential, e := store.RevealCredential(ctx, wireNode.CredentialID)
	if e != nil {
		t.Fatal(e)
	}
	direct, e := (native.ShadowQUICOutboundFactory{}).Build(underlay.WithFactory(ctx, underlay.New()), wireNode, wireCredential)
	if e != nil {
		t.Fatal(e)
	}
	defer direct.Close()
	// Recompile the existing inbound after enabling Core DNS, through the shared
	// binding service, so its immutable runtime captures the current DNS owner.
	inbound, e := s.Inbound(ctx, created.InboundID)
	if e != nil {
		t.Fatal(e)
	}
	committed, e := store.State(ctx)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.SetBinding(ctx, created.InboundID, application.BindingRequest{BindingID: inbound.Bindings[0].BindingID, Enabled: true, ResourceRevision: inbound.Bindings[0].Revision, Revision: committed.Revision})
	if e != nil {
		t.Fatal(e)
	}
	wireTarget := target
	wireTarget.Host = "server-managed.test"
	stream, e := direct.DialContext(ctx, wireTarget)
	if e != nil {
		t.Fatal(e)
	}
	_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
	checkHeld(t, stream, "server Core DNS TCP")
	stream.Close()
	wireUDP := udp
	wireUDP.Host = "server-managed.test"
	p, e := direct.(ports.ClientPacketDialer).ListenPacket(ctx, wireUDP)
	if e != nil {
		t.Fatal(e)
	}
	_ = p.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = p.WriteTo([]byte("server Core DNS UDP"), netaddr.UDP(wireUDP)); e != nil {
		t.Fatal(e)
	}
	var scratch [1200]byte
	count, reply, e := p.ReadFrom(scratch[:])
	p.Close()
	if e != nil || string(scratch[:count]) != "server Core DNS UDP" || reply.String() != netaddr.UDP(wireUDP).String() {
		t.Fatal("server DNS UDP", e)
	}
	stream, e = direct.DialContext(ctx, missing)
	if e == nil {
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = stream.Write([]byte{1})
		var b [1]byte
		if _, e = stream.Read(b[:]); e == nil {
			t.Fatal("server NXDOMAIN bypass")
		}
		stream.Close()
	}
	if ambient.Load() != 0 {
		t.Fatal("server system DNS fallback", ambient.Load())
	}
	// A hostname node is bootstrapped through the same committed Core DNS.
	status, e := s.ClientStatus(ctx)
	if e != nil {
		t.Fatal(e)
	}
	n := status.State.Nodes[0]
	n.Endpoint.Host = "proxy.fixture.local"
	clientApply(t, s, application.ClientMutation{Resource: "node", Action: "update", ID: n.ID, Node: &n})
	if e = transfer(local, target, []byte("Core proxy bootstrap")); e != nil {
		t.Fatal(e)
	}
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
	if e = transfer(local, target, []byte("client restart")); e != nil {
		t.Fatal(e)
	}
	stop(t, s, store)
	closed = true
	s, store = setupProtocols(t, path, nil, registry.NativeCore)
	closed = false
	if e = s.EnableClientRuntime(ctx, adapters); e != nil {
		t.Fatal(e)
	}
	if e = transfer(local, target, []byte("SQLite restart")); e != nil {
		t.Fatal(e)
	}
	stop(t, s, store)
	closed = true
	backup := filepath.Join(root, "backup", "state.db")
	schema, e := sqlite.MaintenanceBackup(ctx, path, backup)
	if e != nil || schema != 8 {
		t.Fatal("backup", schema, e)
	}
	raw, e := os.ReadFile(backup)
	if e != nil || bytes.Contains(raw, []byte("synthetic-shadow-secret")) {
		t.Fatal("secret persistence", e)
	}
	restored, rs := setupProtocols(t, backup, nil, registry.NativeCore)
	defer stop(t, restored, rs)
	if e = restored.EnableClientRuntime(ctx, adapters); e != nil {
		t.Fatal(e)
	}
	if e = transfer(local, target, []byte("backup restore")); e != nil {
		t.Fatal(e)
	}
	if ambient.Load() != 0 {
		t.Fatal("system fallback", ambient.Load())
	}
}

func TestShadowQUICAPIAndCLIShareCreation(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "private", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	queries := transport.TestClient(server.Client(), server.URL)
	defer queries.Close()
	doc := []byte(`{"schema":1,"name":"ShadowQUIC plan","listener":{"host":"127.0.0.1","port":443},"display_endpoint":{"host":"public.test","port":443},"settings":{"server_name":"cover.test","camouflage_endpoint":{"host":"127.0.0.1","port":443}},"users":[{"account_name":"Display only","username":"auth-user","password":"synthetic-private-secret"}]}`)
	if p, e := queries.PlanCreation(ctx, "shadowquic", doc); e != nil || p.Protocol != module.Key() {
		t.Fatal(e, p)
	}
	file := filepath.Join(t.TempDir(), "creation.json")
	if e := os.WriteFile(file, doc, 0o600); e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"validate", "plan"} {
		var out, errOut bytes.Buffer
		if code := cli.Run(ctx, []string{"inbound", action, "--protocol", "shadowquic", "--file", file}, &out, &errOut, cli.Dependencies{Build: version.Current(), Queries: queries}); code != 0 {
			t.Fatal(code, errOut.String())
		}
		if bytes.Contains(out.Bytes(), []byte("synthetic-private-secret")) {
			t.Fatal("CLI secret")
		}
	}
}

func shadowQUICDNS(t *testing.T, counter *atomic.Int64) access.Endpoint {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &dns.Server{PacketConn: p, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		counter.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "missing.fixture.local." {
			m.Rcode = dns.RcodeNameError
		} else if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(m)
	})}
	ready, done := make(chan struct{}), make(chan error, 1)
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		_ = s.Shutdown()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(p.LocalAddr().(*net.UDPAddr).Port)}
}

func TestShadowQUICCamouflageCoreDNSAndNXDOMAIN(t *testing.T) {
	ambient := isolatedResolver(t)
	if ambient == nil {
		return
	}
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "private", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	adapters, e := registry.NewOutbounds(native.ShadowQUICOutboundFactory{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(ctx, adapters); e != nil {
		t.Fatal(e)
	}
	var queries atomic.Int64
	endpoint := shadowQUICDNS(t, &queries)
	id := networkID(t)
	applyNetwork(t, s, P.Config{Servers: []P.DNSServer{{ID: id, Name: "bootstrap", Type: "udp", Endpoint: endpoint, Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: id, BootstrapServer: id, Strategy: "ipv4_only", TimeoutSeconds: 1}})
	for _, host := range []string{"cover.fixture.local", "missing.fixture.local"} {
		port := udpPort(t)
		doc, _ := json.Marshal(map[string]any{"schema": 1, "name": "Camouflage bootstrap", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "127.0.0.1", Port: port}, "settings": module.Settings{ServerName: "cover.test", Camouflage: access.Endpoint{Host: host, Port: 443}}, "users": []any{map[string]any{"account_name": "Alpha"}}})
		plan, e := s.PlanCreation(ctx, "shadowquic", doc)
		if e != nil {
			t.Fatal(e)
		}
		_, e = s.ApplyCreation(ctx, "shadowquic", application.ApplyRequest{Document: doc, Digest: plan.Digest, Revision: plan.Revision})
		if host == "cover.fixture.local" && e != nil {
			t.Fatal(e)
		}
		if host == "missing.fixture.local" && e == nil {
			t.Fatal("camouflage NXDOMAIN accepted")
		}
	}
	if ambient.Load() != 0 || queries.Load() < 2 {
		t.Fatal("camouflage DNS ownership", ambient.Load(), queries.Load())
	}
}
