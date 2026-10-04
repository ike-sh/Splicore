package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type managementFeed struct {
	mu         sync.Mutex
	body, etag string
	status     int
	calls      int
}

func (f *managementFeed) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	w.Header().Set("Content-Type", "text/plain")
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if f.etag != "" {
		w.Header().Set("ETag", f.etag)
		if r.Header.Get("If-None-Match") == f.etag {
			w.WriteHeader(304)
			return
		}
	}
	_, _ = io.WriteString(w, f.body)
}
func (f *managementFeed) set(body, etag string, status int) {
	f.mu.Lock()
	f.body = body
	f.etag = etag
	f.status = status
	f.mu.Unlock()
}
func managementApply(t *testing.T, s *application.Service, r application.ManagementRequest) application.ManagementPreview {
	t.Helper()
	p, e := s.PreviewManagement(context.Background(), r)
	if e != nil {
		t.Fatal("preview", e)
	}
	if !p.Applicable {
		t.Fatalf("preview rejected: %s %+v", p.Reason, p.Entries)
	}
	_, e = s.ApplyManagement(context.Background(), application.ManagementApply{Token: p.Token, Revision: p.Revision})
	if e != nil {
		t.Fatal("apply", e)
	}
	return p
}
func providerNodes(t *testing.T, s *application.Service, id identity.ID) []client.RemoteNode {
	t.Helper()
	status, e := s.ClientStatus(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return slices.DeleteFunc(status.State.Nodes, func(n client.RemoteNode) bool { return n.Provenance.ProviderID != id })
}
func snellCandidate(key string, endpoint access.Endpoint, psk string) nodeimport.Candidate {
	return nodeimport.Candidate{Key: key, Node: client.RemoteNode{Name: key, Protocol: sm.Key(6), Endpoint: endpoint, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":6}`)}}, Credential: nodeimport.Credential{Kind: access.PSK, Value: psk}}
}
func feedDocument(c []nodeimport.Candidate) string {
	b, _ := json.Marshal(nodeimport.Document{Schema: 1, Nodes: c})
	return string(b)
}
func nodeIDs(nodes []client.RemoteNode) map[string]identity.ID {
	m := map[string]identity.ID{}
	for _, n := range nodes {
		m[n.Provenance.Key] = n.ID
	}
	return m
}
func TestPhase14ProviderLifecycleTraffic(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupSnell(t, path, nil)
	enableClient(t, s)
	closed := false
	t.Cleanup(func() {
		if !closed {
			stop(t, s, store)
		}
	})
	remote := freePort(t)
	created := apply(t, s, doc(remote, 6))
	psk := remotePSK(t, store, created.InboundID)
	entries := []nodeimport.Candidate{}
	for i := 0; i < 10; i++ {
		entries = append(entries, snellCandidate(fmt.Sprintf("native-%02d", i), access.Endpoint{Host: "127.0.0.1", Port: remote}, psk))
	}
	feed := &managementFeed{}
	feed.set(feedDocument(entries), "generation-1", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	preview := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "fixture", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL + "/token?unknown-secret=SOURCE_SECRET", Auth: &provider.Auth{Type: "bearer", Value: "AUTH_SECRET"}}})
	id := preview.ProviderID
	before, _ := s.ClientStatus(ctx)
	p, e := s.PreviewProviderRefresh(ctx, id)
	if e != nil || !p.Applicable || len(p.Entries) != 10 {
		t.Fatal("initial preview", p, e)
	}
	after, _ := s.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State, after.State) {
		t.Fatal("preview wrote state")
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), psk) || strings.Contains(string(b), "SOURCE_SECRET") {
		t.Fatal("preview secret")
	}
	_, e = s.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision})
	if e != nil {
		t.Fatal(e)
	}
	nodes := providerNodes(t, s, id)
	ids := nodeIDs(nodes)
	if len(ids) != 10 {
		t.Fatal("initial node count")
	}
	status, _ := s.ClientStatus(ctx)
	oid := identity.ID("")
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == nodes[0].ID {
			oid = o.ID
		}
	}
	local := freePort(t)
	addLocal(t, s, local, oid)
	target := echoTarget(t, "127.0.0.1")
	if e = transfer(local, target, bytes.Repeat([]byte("provider-initial"), 2048)); e != nil {
		t.Fatal("initial traffic", e)
	}
	waitIdle(t, s)
	for range 10 {
		slices.Reverse(entries)
		for i := range entries {
			entries[i].Node.Name = "renamed-" + entries[i].Key
		}
		feed.set(feedDocument(entries), "", 0)
		if _, e = s.RefreshProvider(ctx, id); e != nil {
			t.Fatal("refresh", e)
		}
		if !reflect.DeepEqual(ids, nodeIDs(providerNodes(t, s, id))) {
			t.Fatal("reorder/rename identity")
		}
		if e = transfer(local, target, []byte("rename-survives")); e != nil {
			t.Fatal(e)
		}
		waitIdle(t, s)
	}
	// Keep a live old-generation stream while rotating to another owned server.
	remote2 := freePort(t)
	created2 := apply(t, s, doc(remote2, 6))
	psk2 := remotePSK(t, store, created2.InboundID)
	held, e := socksConn(local, target)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	heldEcho := func() {
		t.Helper()
		payload := []byte("retained-old-generation")
		if _, e := held.Write(payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(held, b); e != nil || !bytes.Equal(payload, b) {
			t.Fatal("old generation lost", e)
		}
	}
	heldEcho()
	for i := 0; i < 10; i++ {
		chosen, secret := remote2, psk2
		if i%2 == 1 {
			chosen, secret = remote, psk
		}
		for j := range entries {
			entries[j].Node.Endpoint.Port = chosen
			entries[j].Credential.Value = secret
		}
		feed.set(feedDocument(entries), "", 0)
		if _, e = s.RefreshProvider(ctx, id); e != nil {
			t.Fatal("rotation", e)
		}
		if !reflect.DeepEqual(ids, nodeIDs(providerNodes(t, s, id))) {
			t.Fatal("rotation identity")
		}
		if e = transfer(local, target, []byte("new-credential-generation")); e != nil {
			t.Fatal(e)
		}
		heldEcho()
	}
	held.Close()
	waitIdle(t, s)
	// ETag / 304 leaves provider generation and adapter leases unchanged.
	feed.set(feedDocument(entries), "generation-final", 0)
	if _, e = s.RefreshProvider(ctx, id); e != nil {
		t.Fatal(e)
	}
	before, _ = s.ClientStatus(ctx)
	if _, e = s.RefreshProvider(ctx, id); e != nil {
		t.Fatal(e)
	}
	after, _ = s.ClientStatus(ctx)
	if before.State.Management.Providers[0].Generation != after.State.Management.Providers[0].Generation || before.Underlay.Acquires != after.Underlay.Acquires-1 {
		t.Fatal("304 generation churn")
	}
	// Fetch via a manual independent proxy outbound, then reject self dependency.
	manual := addNode(t, s, access.Endpoint{Host: "127.0.0.1", Port: remote}, 6, psk)
	fetchOut := addProxy(t, s, manual)
	config := after.State.Management.Providers[0]
	config.Generation = 0
	config.Status = ""
	config.URLDisplay = ""
	config.LastSuccess = time.Time{}
	config.LastFailure = time.Time{}
	config.LastError = ""
	config.Failures = 0
	config.FetchAction = P.Action{Kind: P.Outbound, ID: fetchOut}
	managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", ID: id, Provider: &config})
	feed.set(feedDocument(entries), "", 0)
	if _, e = s.RefreshProvider(ctx, id); e != nil {
		t.Fatal("fetch via proxy", e)
	}
	config.FetchAction = P.Action{Kind: P.Outbound, ID: oid}
	p, e = s.PreviewManagement(ctx, application.ManagementRequest{Operation: "provider-upsert", ID: id, Provider: &config})
	if e != nil || p.Applicable {
		t.Fatal("self dependency not rejected", e)
	}
	// Complete failures and invalid feeds retain last-good nodes and traffic.
	for range 10 {
		old := providerNodes(t, s, id)
		feed.set("", "", 503)
		if _, e = s.RefreshProvider(ctx, id); e == nil {
			t.Fatal("failure accepted")
		}
		if !reflect.DeepEqual(old, providerNodes(t, s, id)) {
			t.Fatal("failure changed nodes")
		}
		if e = transfer(local, target, []byte("last-good")); e != nil {
			t.Fatal(e)
		}
		waitIdle(t, s)
	}
	feed.set(feedDocument(entries[:1])+"garbage", "", 0)
	if _, e = s.RefreshProvider(ctx, id); e == nil {
		t.Fatal("invalid feed accepted")
	}
	feed.set(feedDocument(nil), "", 0)
	if _, e = s.RefreshProvider(ctx, id); e == nil {
		t.Fatal("empty feed accepted")
	}
	feed.set(feedDocument(entries[:4]), "", 0)
	p, e = s.PreviewProviderRefresh(ctx, id)
	if e != nil || p.Applicable || p.Reason != "safety_guard" {
		t.Fatal("mass delete guard", p, e)
	}
	// Remove two nodes: selected one stays stale, the unreferenced one disappears.
	selected := nodes[0].ID
	filtered := []nodeimport.Candidate{}
	removedOther := identity.ID("")
	for _, entry := range entries {
		nid := ids[nodeimport.LogicalKey(entry)]
		if nid == selected {
			continue
		}
		if removedOther == "" {
			removedOther = nid
			continue
		}
		filtered = append(filtered, entry)
	}
	feed.set(feedDocument(filtered), "", 0)
	if _, e = s.RefreshProvider(ctx, id); e != nil {
		t.Fatal("removal", e)
	}
	nodes = providerNodes(t, s, id)
	if len(nodes) != 9 {
		t.Fatal("removed count", len(nodes))
	}
	foundStale := false
	for _, n := range nodes {
		if n.ID == selected {
			foundStale = n.State == "stale"
		}
		if n.ID == removedOther {
			t.Fatal("unreferenced not removed")
		}
	}
	if !foundStale {
		t.Fatal("referenced not stale")
	}
	if e = transfer(local, target, []byte("stale-policy-retains")); e != nil {
		t.Fatal(e)
	}
	waitIdle(t, s)
	p, e = s.PreviewManagement(ctx, application.ManagementRequest{Operation: "provider-delete", ID: id})
	if e != nil || p.Applicable {
		t.Fatal("referenced provider delete accepted")
	}
	managementApply(t, s, application.ManagementRequest{Operation: "batch", Action: "tag", IDs: []identity.ID{selected}, Tags: []string{"operator-tag"}})
	exported, e := s.ExportNodes(ctx, application.NodeExportRequest{Format: "canonical", ProviderID: id, RevealSecrets: true})
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := nodeimport.Parse("canonical", []byte(exported.Content))
	if e != nil || len(parsed.Candidates) != 9 {
		t.Fatal("export round trip", e)
	}
	// Offline reopen restores committed nodes, tags, credentials and traffic.
	stop(t, s, store)
	closed = true
	fixture.Close()
	s2, store2 := setupSnell(t, path, nil)
	enableClient(t, s2)
	defer stop(t, s2, store2)
	if len(providerNodes(t, s2, id)) != 9 {
		t.Fatal("offline restore")
	}
	if e = transfer(local, target, []byte("offline-restart")); e != nil {
		t.Fatal("offline traffic", e)
	}
	waitIdle(t, s2)
	for range 10 {
		if e = s2.StartManagement(ctx); e != nil {
			t.Fatal(e)
		}
		if e = s2.StopManagementScheduler(ctx); e != nil {
			t.Fatal(e)
		}
	}
}

func TestPhase14RulesAPIAndConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	enableClient(t, s)
	feed := &managementFeed{}
	feed.set(`{"schema_version":1,"rules":[{"ip_cidrs":["127.0.0.1/32"]}]}`, "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	apiFixture := httptest.NewServer(api.Handler(s))
	defer apiFixture.Close()
	ctl := transport.TestClient(apiFixture.Client(), apiFixture.URL)
	defer ctl.Close()
	p, e := ctl.PreviewManagement(ctx, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "rules", Kind: "ruleset", Format: "canonical-rules", AllowPrivate: true, MaxDeletePercent: 100}, Source: &provider.Source{URL: fixture.URL}})
	if e != nil || !p.Applicable {
		t.Fatal(e, p.Reason)
	}
	if _, e = ctl.ApplyManagement(ctx, application.ManagementApply{Token: p.Token, Revision: p.Revision}); e != nil {
		t.Fatal(e)
	}
	id := p.ProviderID
	if _, e = ctl.RefreshProvider(ctx, id); e != nil {
		t.Fatal(e)
	}
	status, _ := s.ClientStatus(ctx)
	set := status.State.Management.Providers[0].RuleSetID
	rid, _ := identity.NewID()
	clientApply(t, s, application.ClientMutation{Resource: "route-rule", Action: "create", RouteRule: &P.RouteRule{ID: rid, Name: "remote-rule", Match: P.RuleMatch{RuleSets: []identity.ID{set}}, Action: P.Action{Kind: P.Reject}}})
	local := freePort(t)
	addLocal(t, s, local, "")
	target := echoTarget(t, "127.0.0.1")
	for i := 0; i < 10; i++ {
		cidr := "127.0.0.1/32"
		if i%2 == 1 {
			cidr = "192.0.2.1/32"
		}
		feed.set(fmt.Sprintf(`{"schema_version":1,"rules":[{"ip_cidrs":[%q]}]}`, cidr), "", 0)
		if _, e = ctl.RefreshProvider(ctx, id); e != nil {
			t.Fatal(e)
		}
		e = transfer(local, target, []byte("rules-atomic"))
		if (i%2 == 0) != (e != nil) {
			t.Fatal("rules traffic", i, e)
		}
		waitIdle(t, s)
	}
	// Same provider serializes complete refresh/apply; distinct callers cannot overlap fetch.
	failures := make(chan error, 10)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := s.RefreshProvider(ctx, id); failures <- e }()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		if e != nil {
			t.Fatal("serialized refresh", e)
		}
	}
	before, _ := s.ClientStatus(ctx)
	feed.set(`{"schema_version":1,"rules":[{"domain_suffixes":["invalid_domain!"]}]}`, "", 0)
	if _, e = ctl.RefreshProvider(ctx, id); e == nil {
		t.Fatal("invalid rules accepted")
	}
	after, _ := s.ClientStatus(ctx)
	if !reflect.DeepEqual(before.State.Network.RuleSets, after.State.Network.RuleSets) {
		t.Fatal("rules failure changed authority")
	}
	p, e = ctl.PreviewManagement(ctx, application.ManagementRequest{Operation: "provider-delete", ID: id})
	if e != nil || p.Applicable {
		t.Fatal("referenced rules deletion")
	}
}
