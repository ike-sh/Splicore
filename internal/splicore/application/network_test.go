package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/cli"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func networkID(t *testing.T) identity.ID {
	t.Helper()
	id, e := identity.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func appDNS(t *testing.T, network string, counter *atomic.Int64) access.Endpoint {
	t.Helper()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		counter.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		}
		if q.Qtype == dns.TypeAAAA {
			m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("::1")}}
		}
		_ = w.WriteMsg(m)
	})
	s := &dns.Server{Net: network, Handler: handler}
	var port int
	var err error
	if network == "udp" {
		s.PacketConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err == nil {
			port = s.PacketConn.LocalAddr().(*net.UDPAddr).Port
		}
	} else {
		s.Listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			port = s.Listener.Addr().(*net.TCPAddr).Port
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		_ = s.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(port)}
}
func applyNetwork(t *testing.T, s *application.Service, c P.Config) {
	t.Helper()
	clientApply(t, s, application.ClientMutation{Resource: "network", Action: "replace", Network: &c})
}
func checkHeld(t *testing.T, c net.Conn, body string) {
	t.Helper()
	if _, err := c.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(body))
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != body {
		t.Fatal("held connection changed", err)
	}
}
func TestNetworkControlTransactionsReferencesRecovery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	var repository *clientCommitFailure
	s, store := setupSnell(t, path, func(r ports.RuntimeRepository) ports.Repository {
		repository = &clientCommitFailure{ClientRepository: r.(ports.ClientRepository)}
		return repository
	})
	defer func() { stop(t, s, store) }()
	enableClient(t, s)
	local := freePort(t)
	in := addLocal(t, s, local, "")
	node := addNode(t, s, access.Endpoint{Host: "127.0.0.1", Port: 12345}, 5, "SyntheticNetworkPSK123456")
	outbound := addProxy(t, s, node)
	member := P.Action{Kind: P.Direct}
	group := networkID(t)
	set := networkID(t)
	serverID := networkID(t)
	var dnsQueries atomic.Int64
	endpoint := appDNS(t, "udp", &dnsQueries)
	c := P.Config{Route: P.RouteProfile{Final: &P.Action{Kind: P.Group, ID: group}, Rules: []P.RouteRule{{ID: networkID(t), Name: "safe reject", Match: P.RuleMatch{Domains: []string{"reject.test"}}, Action: P.Action{Kind: P.Reject}}}},
		Groups:   []P.PolicyGroup{{ID: group, Name: "selector", Type: "selector", Members: []P.Action{member, {Kind: P.Outbound, ID: outbound}}, Selector: &P.SelectorSettings{Selected: member}}},
		RuleSets: []P.RuleSet{{ID: set, Name: "domains", Type: "inline", Status: "enabled", Revision: 1, Rules: []P.RuleMatch{{Suffixes: []string{"direct.test"}}}}},
		Servers:  []P.DNSServer{{ID: serverID, Name: "resolver", Type: "udp", Endpoint: endpoint, Detour: P.Action{Kind: P.Direct}}},
		DNSRules: []P.DNSRule{{ID: networkID(t), Name: "split", Match: P.RuleMatch{RuleSets: []identity.ID{set}}, Server: serverID}},
		DNS:      P.DNSProfile{Enabled: true, DefaultServer: serverID, BootstrapServer: serverID, Strategy: "ipv4_only", Cache: P.DNSCachePolicy{Capacity: 8}, TimeoutSeconds: 2}}
	applyNetwork(t, s, c)
	target := echoTarget(t, "127.0.0.1")
	held, err := socksConn(local, target)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	checkHeld(t, held, "before")
	before, _ := s.ClientStatus(ctx)
	changed := c.Clone()
	changed.Groups[0].Name = "renamed"
	b, _ := json.Marshal(application.ClientMutation{Resource: "network", Action: "replace", Network: &changed})
	plan, err := s.PlanClient(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	repository.fail.Store(true)
	if _, err = s.ApplyClient(ctx, application.ApplyRequest{Document: b, Digest: plan.Digest, Revision: plan.Revision}); err == nil {
		t.Fatal("commit fault accepted")
	}
	repository.fail.Store(false)
	after, _ := s.ClientStatus(ctx)
	if after.State.Revision != before.State.Revision || after.State.Network.Groups[0].Name != "selector" {
		t.Fatal("failed snapshot published")
	}
	checkHeld(t, held, "after failed commit")
	for _, m := range []application.ClientMutation{
		{Resource: "outbound", Action: "delete", ID: outbound}, {Resource: "policy-group", Action: "delete", ID: group}, {Resource: "rule-set", Action: "delete", ID: set}, {Resource: "dns-server", Action: "delete", ID: serverID},
		{Resource: "policy-group", Action: "select", ID: group, Selected: &P.Action{Kind: P.Outbound, ID: networkID(t)}},
	} {
		raw, _ := json.Marshal(m)
		if _, err = s.PlanClient(ctx, raw); err == nil {
			t.Fatal("dangling reference admitted", m.Resource)
		}
	}
	h := httptest.NewServer(api.Handler(s))
	defer h.Close()
	ctl := transport.TestClient(h.Client(), h.URL)
	defer ctl.Close()
	call := func(method, path string, body any, expected int) []byte {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, h.URL+path, bytes.NewReader(raw))
		st, _ := s.ClientStatus(ctx)
		req.Header.Set("If-Match", fmt.Sprintf("\"%d\"", st.State.Revision))
		res, err := h.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ = io.ReadAll(res.Body)
		if res.StatusCode != expected {
			t.Fatal(path, res.StatusCode, string(raw))
		}
		if bytes.Contains(raw, []byte("SyntheticNetworkPSK123456")) {
			t.Fatal("secret leak")
		}
		return raw
	}
	for _, path := range []string{"routes", "route-rules", "rule-sets", "policy-groups", "policy-groups/status", "dns/servers", "dns/rules", "dns/profile", "dns/cache/status"} {
		call("GET", "/api/v1/"+path, nil, 200)
		call("PATCH", "/api/v1/"+path, nil, 405)
	}
	call("GET", "/api/v1/dns/unknown", nil, 404)
	q := networkruntime.Query{Domain: "reject.test", Port: 443, Network: "tcp", LocalInbound: in}
	count := dnsQueries.Load()
	call("POST", "/api/v1/routes/explain", q, 200)
	if dnsQueries.Load() != count {
		t.Fatal("explain performed DNS")
	}
	if _, err = socksConn(local, access.Endpoint{Host: "reject.test", Port: 443}); err == nil {
		t.Fatal("REJECT connected")
	}
	if dnsQueries.Load() != count {
		t.Fatal("first-rule REJECT leaked DNS")
	}
	call("POST", "/api/v1/dns/lookup", map[string]string{"domain": "live.direct.test"}, 200)
	call("POST", "/api/v1/dns/cache/flush", map[string]bool{}, 200)
	call("POST", "/api/v1/policy-groups/"+string(group)+"/select", map[string]any{"selected": member}, 200)
	route := changed.Route
	call("PUT", "/api/v1/routes", map[string]any{"route_profile": route}, 200)
	call("PUT", "/api/v1/dns/profile", map[string]any{"dns_profile": changed.DNS}, 200)
	call("PUT", "/api/v1/policy-groups/"+string(group), map[string]any{"policy_group": changed.Groups[0]}, 200)
	// Individual resource endpoints must persist the same canonical objects as bulk replacement.
	for _, resource := range []struct {
		path, field string
		value       any
	}{
		{"route-rules", "route_rule", P.RouteRule{ID: networkID(t), Name: "unused", Match: P.RuleMatch{Domains: []string{"unused.test"}}, Action: member}},
		{"rule-sets", "rule_set", P.RuleSet{ID: networkID(t), Name: "unused", Type: "local", Status: "enabled", Revision: 1, Rules: []P.RuleMatch{{Domains: []string{"unused.test"}}}}},
		{"policy-groups", "policy_group", P.PolicyGroup{ID: networkID(t), Name: "unused", Type: "selector", Members: []P.Action{member}, Selector: &P.SelectorSettings{Selected: member}}},
		{"dns/servers", "dns_server", P.DNSServer{ID: networkID(t), Name: "unused", Type: "system", Detour: member}},
		{"dns/rules", "dns_rule", P.DNSRule{ID: networkID(t), Name: "unused", Match: P.RuleMatch{Domains: []string{"unused.test"}}, Server: serverID}},
	} {
		encoded, _ := json.Marshal(resource.value)
		var value map[string]any
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		path := "/api/v1/" + resource.path
		call("POST", path, map[string]any{resource.field: value}, 200)
		path += "/" + value["id"].(string)
		value["name"] = "renamed individual resource"
		call("PUT", path, map[string]any{resource.field: value}, 200)
		var restored map[string]any
		if err := json.Unmarshal(call("GET", path, nil, 200), &restored); err != nil || restored["name"] != value["name"] {
			t.Fatal("individual resource was not persisted", path, err)
		}
		call("DELETE", path, nil, 200)
		call("GET", path, nil, 404)
	}
	// An unavailable active group is still explainable. REJECT members cannot dial a probe.
	unavailable := changed.Clone()
	unavailableGroup, unavailableRule := networkID(t), networkID(t)
	unavailable.Groups = append(unavailable.Groups, P.PolicyGroup{ID: unavailableGroup, Name: "all rejected", Type: "fallback", Members: []P.Action{{Kind: P.Reject}}, Fallback: &P.FallbackSettings{Probe: P.Probe{URL: "http://127.0.0.1:1/health", IntervalSeconds: 1, TimeoutSeconds: 1, ExpectedStatus: 204}}})
	unavailable.Route.Rules = append(unavailable.Route.Rules, P.RouteRule{ID: unavailableRule, Name: "unavailable explanation", Match: P.RuleMatch{Domains: []string{"unavailable.test"}}, Action: P.Action{Kind: P.Group, ID: unavailableGroup}})
	applyNetwork(t, s, unavailable)
	count = dnsQueries.Load()
	var explanation networkruntime.Explanation
	if err := json.Unmarshal(call("POST", "/api/v1/routes/explain", networkruntime.Query{Domain: "unavailable.test", Port: 443, Network: "tcp", LocalInbound: in}, 200), &explanation); err != nil || explanation.Available || explanation.Rule != unavailableRule || explanation.Group != unavailableGroup {
		t.Fatal("unavailable group explanation", explanation, err)
	}
	if dnsQueries.Load() != count {
		t.Fatal("unavailable explanation performed DNS")
	}
	applyNetwork(t, s, changed)
	q.IP = netip.MustParseAddr("127.0.0.1")
	queryFile := filepath.Join(t.TempDir(), "query.json")
	raw, _ := json.Marshal(q)
	if err = os.WriteFile(queryFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	deps := cli.Dependencies{Queries: ctl, Build: version.Current()}
	for _, args := range [][]string{{"network", "export"}, {"route", "status"}, {"route", "explain", "--file", queryFile}, {"policy", "list"}, {"policy", "status"}, {"dns", "status"}, {"dns", "lookup", "--domain", "cli.direct.test"}, {"dns", "flush"}, {"rule-set", "list"}, {"route-rule", "list"}} {
		out.Reset()
		errOut.Reset()
		if cli.Run(ctx, args, &out, &errOut, deps) != 0 {
			t.Fatal(args, errOut.String())
		}
	}
	// Exported canonical Config is accepted unchanged by validate, plan and apply.
	exportFile, planPath := filepath.Join(t.TempDir(), "network.json"), filepath.Join(t.TempDir(), "plan.json")
	out.Reset()
	if cli.Run(ctx, []string{"network", "export"}, &out, &errOut, deps) != 0 {
		t.Fatal(errOut.String())
	}
	exported := append([]byte(nil), out.Bytes()...)
	if err := os.WriteFile(exportFile, exported, 0600); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"validate", "plan", "apply"} {
		out.Reset()
		args := []string{"network", operation, "--file", exportFile}
		if operation == "apply" {
			args = append(args, "--plan", planPath)
		}
		if cli.Run(ctx, args, &out, &errOut, deps) != 0 {
			t.Fatal(operation, errOut.String())
		}
		if operation == "plan" {
			if err := os.WriteFile(planPath, out.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	var exportedConfig P.Config
	if err := json.Unmarshal(exported, &exportedConfig); err != nil {
		t.Fatal(err)
	}
	current, _ := s.ClientStatus(ctx)
	want, _ := json.Marshal(exportedConfig)
	got, _ := json.Marshal(current.State.Network)
	if !bytes.Equal(want, got) {
		t.Fatal("canonical export/import changed the network graph")
	}
	// Restart recreates the graph from SQLite; observational caches are discarded.
	held.Close()
	waitIdle(t, s)
	stop(t, s, store)
	s, store = setupSnell(t, path, nil)
	enableClient(t, s)
	restored, err := s.ClientStatus(ctx)
	if err != nil || restored.State.Network.Groups[0].Name != "renamed" || restored.State.Network.Groups[0].Selector.Selected != member || len(restored.State.Network.DNSRules) != 1 || restored.Network.DNS.Entries != 0 {
		t.Fatal("canonical recovery", err)
	}
	if err = transfer(local, target, []byte("restored direct")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DNSLookup(ctx, "restart.direct.test"); err != nil {
		t.Fatal(err)
	}
	// Configuration can be edited while stopped, then restarted without losing references.
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	applyNetwork(t, s, restored.State.Network)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
	if err = transfer(local, target, []byte("stopped graph")); err != nil {
		t.Fatal(err)
	}
}

type corruptClientRepo struct{ ports.ClientRepository }

func (c corruptClientRepo) ClientState(context.Context) (client.ProfileState, error) {
	return client.ProfileState{}, identity.Err(identity.Corrupt, "synthetic corrupt committed graph")
}
func TestCorruptNetworkStartupKeepsServerControlAvailable(t *testing.T) {
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "private", "state.db"), func(r ports.RuntimeRepository) ports.Repository { return corruptClientRepo{r.(ports.ClientRepository)} })
	defer stop(t, s, store)
	enableClient(t, s)
	status, err := s.ClientStatus(context.Background())
	if err != nil || status.Health != "degraded" || status.LastError != "client_committed_state_invalid" {
		t.Fatal(status, err)
	}
	if _, err = s.System(context.Background()); err != nil {
		t.Fatal("server control disabled by client graph", err)
	}
	if _, err = s.RouteExplain(context.Background(), networkruntime.Query{Domain: "local.test", Network: "tcp", Port: 80}); err == nil {
		t.Fatal("corrupt client admitted routing")
	}
	state, err := store.ClientState(context.Background())
	if err != nil || state.Revision != 0 {
		t.Fatal("startup rewrote user state", err)
	}
}

func TestShutdownCancelsDNSQueryRetainingRetiredGraph(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "private", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	entered := make(chan struct{}, 1)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	resolver := &dns.Server{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) { entered <- struct{}{} }), NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- resolver.ActivateAndServe() }()
	<-ready
	defer func() {
		_ = resolver.Shutdown()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	id := networkID(t)
	c := P.Config{Servers: []P.DNSServer{{ID: id, Name: "silent owned resolver", Type: "udp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: uint16(pc.LocalAddr().(*net.UDPAddr).Port)}, Detour: P.Action{Kind: P.Direct}}},
		DNS: P.DNSProfile{Enabled: true, DefaultServer: id, BootstrapServer: id, Strategy: "ipv4_only", TimeoutSeconds: 10}}
	applyNetwork(t, s, c)
	queryDone := make(chan error, 1)
	go func() { _, err := s.DNSLookup(ctx, "pending.test"); queryDone <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("DNS query never reached fixture")
	}
	// The query now owns the old generation; publishing another graph must retain it.
	c.Route.Final = &P.Action{Kind: P.Reject}
	applyNetwork(t, s, c)
	closeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := s.CloseClientRuntime(closeCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-queryDone:
		if err == nil {
			t.Fatal("canceled query succeeded")
		}
	case <-closeCtx.Done():
		t.Fatal("retired DNS owner survived shutdown")
	}
}
