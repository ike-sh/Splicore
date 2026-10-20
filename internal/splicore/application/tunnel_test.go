package application_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func TestTunnelSQLiteAPIRecovery(t *testing.T) {
	testTunnelSQLiteAPIRecovery(t, false)
}

func TestTunnelCoreDNSSQLiteAPIRecovery(t *testing.T) {
	testTunnelSQLiteAPIRecovery(t, true)
}

func testTunnelSQLiteAPIRecovery(t *testing.T, managedDNS bool) {
	ctx := context.Background()
	var coreQueries, systemQueries atomic.Int64
	if managedDNS {
		previous := net.DefaultResolver
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
			systemQueries.Add(1)
			return nil, errors.New("SQLite tunnel test forbids system DNS")
		}}
		t.Cleanup(func() { net.DefaultResolver = previous })
	}
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupSnell(t, path, nil)
	enableClient(t, s)
	defer func() { stop(t, s, store) }()
	target := echoTarget(t, "127.0.0.1")
	if managedDNS {
		target.Host = "guard-target.test"
	}
	id := networkID(t)
	in := client.LocalInbound{ID: id, Name: "persisted guard", Kind: "tunnel", Listen: access.Endpoint{Host: "127.0.0.1", Port: freePort(t)}, Tunnel: &client.TunnelSettings{Target: target, Network: "tcp"}, Sniffing: &client.SniffingPolicy{Enabled: true, Protocols: []string{"tls"}, RouteOnly: true}}
	h := httptest.NewServer(api.Handler(s))
	ctl := transport.TestClient(h.Client(), h.URL)
	mutation, _ := json.Marshal(application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &in})
	plan, e := ctl.PlanClient(ctx, mutation)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ctl.ApplyClient(ctx, application.ApplyRequest{Document: mutation, Digest: plan.Digest, Revision: plan.Revision}); e != nil {
		t.Fatal(e)
	}
	// Configure a complete ordered policy through the existing native mutation.
	routes := P.RouteProfile{Rules: []P.RouteRule{{ID: networkID(t), Name: "allow", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}, SniffedDomains: []string{"www.3verge.com"}}, Action: P.Action{Kind: P.Direct}}, {ID: networkID(t), Name: "deny", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}}, Action: P.Action{Kind: P.Reject}}}}
	network := P.Config{Route: routes}
	if managedDNS {
		dnsID := networkID(t)
		network.Servers = []P.DNSServer{{ID: dnsID, Name: "persisted Core DNS", Type: "udp", Endpoint: appDNS(t, "udp", &coreQueries), Detour: P.Action{Kind: P.Direct}}}
		network.DNS = P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: dnsID, Strategy: "ipv4_only", TimeoutSeconds: 1, Cache: P.DNSCachePolicy{Capacity: 8}}
	}
	clientApply(t, s, application.ClientMutation{Resource: "network", Action: "replace", Network: &network})
	status, e := ctl.ClientStatus(ctx)
	if e != nil || len(status.State.LocalInbounds) != 1 || status.State.LocalInbounds[0].Tunnel.Target != target {
		t.Fatal("API serialization lost tunnel", e)
	}
	persistedNetwork := status.State.Network
	bad := in
	bad.Listen.Host = "0.0.0.0"
	bad.AllowLAN = true
	mutation, _ = json.Marshal(application.ClientMutation{Resource: "local-inbound", Action: "update", ID: id, LocalInbound: &bad})
	if _, e = ctl.PlanClient(ctx, mutation); e == nil {
		t.Fatal("public guard accepted by API")
	}
	ctl.Close()
	h.Close()
	probe := func() {
		before := coreQueries.Load()
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", in.Listen.Port), time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		hello := testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS13)
		if _, e = c.Write(hello); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(hello))
		if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(hello, got) {
			t.Fatal("persisted route-only tunnel changed bytes", e)
		}
		if managedDNS && (coreQueries.Load() <= before || systemQueries.Load() != 0) {
			t.Fatal("fresh/restored tunnel bypassed persisted Core DNS", coreQueries.Load()-before, systemQueries.Load())
		}
	}
	probe()
	stop(t, s, store)
	s, store = setupSnell(t, path, nil)
	enableClient(t, s)
	status, e = s.ClientStatus(ctx)
	if e != nil || status.Health != "healthy" || status.State.LocalInbounds[0].Tunnel.Target != target || !reflect.DeepEqual(status.State.Network, persistedNetwork) {
		t.Fatal("SQLite restore failed", e)
	}
	probe()
}
