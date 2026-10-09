package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	v "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vlessDoc(t *testing.T, port uint16, s v.Settings, key string) json.RawMessage {
	t.Helper()
	uuid, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	d := map[string]any{"schema": 1, "engine": "native", "name": "synthetic-vless", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "edge.synthetic.test", Port: 443}, "settings": s, "users": []any{map[string]any{"account_name": "Alice", "uuid": string(uuid)}, map[string]any{"account_name": "Bob"}}}
	if key != "" {
		d["server_secret"] = map[string]any{"private_key": key}
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func applyVLESS(t *testing.T, s *application.Service, d json.RawMessage) application.CreationResult {
	t.Helper()
	p, err := s.PlanCreation(context.Background(), "vless", d)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol.Protocol != "vless" || p.Engine != "native" {
		t.Fatal("plan placement")
	}
	a, err := s.ApplyCreation(context.Background(), "vless", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func target(t *testing.T) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}
func TestVLESSRealityPrivateKeyBlockingGateAndRecovery(t *testing.T) {
	if !v.RealityCompiled {
		t.Skip("REALITY requires with_utls")
	}
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupProtocols(t, path, nil, testfixture.Phase5)
	defer func() { stop(t, s, store) }()
	key, pub, err := v.GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	settings := v.Settings{Security: v.Reality, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Reality: &v.RealitySettings{ServerName: "target.synthetic.test", Target: target(t), ShortIDs: []v.ShortID{"abcd", "", "1234567890abcdef"}}}
	port := freePort(t)
	document := vlessDoc(t, port, settings, key.Material.Reveal())
	var supplied struct {
		Users []struct {
			UUID string `json:"uuid"`
		} `json:"users"`
	}
	if err := json.Unmarshal(document, &supplied); err != nil {
		t.Fatal(err)
	}
	aliceUUID := supplied.Users[0].UUID
	a := applyVLESS(t, s, document)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	view, err := client.Inbound(ctx, a.InboundID)
	if err != nil || view.Health != "healthy" || view.Inbound.Engine != "native" || view.Inbound.Protocol.Protocol != "vless" {
		t.Fatal("view", err)
	}
	secrets, err := store.RevealInboundCredentials(ctx, a.InboundID)
	if err != nil || len(secrets) != 1 || secrets[0].Payload.(access.PrivateKeyPayload).Material.Reveal() != key.Material.Reveal() {
		t.Fatal("encrypted server secret projection")
	}
	inbound, _ := store.Inbounds(ctx)
	committed, _ := v.Decode(inbound[0].Settings.Data)
	if committed.Reality.PublicKey != pub || strings.Contains(string(inbound[0].Settings.Data), key.Material.Reveal()) {
		t.Fatal("public/private settings boundary")
	}
	diagnostics, _ := s.Doctor(ctx, "test")
	ordinary, _ := json.Marshal([]any{view, diagnostics, secrets})
	if strings.Contains(string(ordinary), key.Material.Reveal()) || strings.Contains(string(ordinary), aliceUUID) {
		t.Fatal("ordinary API leaked secret")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", secrets, secrets), key.Material.Reveal()) {
		t.Fatal("diagnostic key leak")
	}
	for _, b := range a.Bindings {
		for _, request := range []application.ExportRequest{{Format: ports.Mihomo, ClientVersion: "1.19.30", BindingID: b.BindingID}, {Format: ports.SingBox, ClientVersion: "1.14.1", BindingID: b.BindingID}, {Format: ports.URI, BindingID: b.BindingID}} {
			exported, err := client.ExportClient(ctx, a.InboundID, request)
			if err != nil {
				t.Fatal("export", err)
			}
			response, _ := json.Marshal(exported)
			if strings.Contains(string(response), key.Material.Reveal()) || strings.Contains(string(response), "private_key") || strings.Contains(exported.Content, `"target":`) || strings.Contains(exported.Content, "127.0.0.1") {
				t.Fatal("BLOCKING SECURITY GATE: server data entered client export")
			}
			if !strings.Contains(exported.Content, string(pub)) || !strings.Contains(exported.Content, "edge.synthetic.test") || !strings.Contains(exported.Content, "target.synthetic.test") {
				t.Fatal("public/endpoint/SNI projection")
			}
			if request.Format == ports.URI {
				if _, err := exporter.ParseVLESSURI(exported.Content); err != nil {
					t.Fatal("URI parse", err)
				}
			}
		}
	}
	page, _ := s.Inbounds(ctx)
	b := a.Bindings[0]
	if _, err := s.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: b.Revision, Revision: page.Revision}); err != nil {
		t.Fatal("reconcile", err)
	}
	if _, err := client.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.URI, BindingID: b.BindingID}); err == nil {
		t.Fatal("disabled export")
	}
	server.Close()
	stop(t, s, store)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), key.Material.Reveal()) || strings.Contains(string(data), aliceUUID) {
		t.Fatal("secret at rest plaintext")
	}
	s, store = setupProtocols(t, path, nil, testfixture.Phase5)
	recovered, err := s.Inbound(ctx, a.InboundID)
	if err != nil || recovered.Health != "healthy" || recovered.Inbound.Engine != "native" {
		t.Fatal("recovery", err)
	}
	for _, binding := range recovered.Bindings {
		if binding.BindingID == b.BindingID && binding.Enabled {
			t.Fatal("disabled resurrected")
		}
	}
	secretAfter, _ := store.RevealInboundCredentials(ctx, a.InboundID)
	if len(secretAfter) != 1 || secretAfter[0].ID != secrets[0].ID || secretAfter[0].Payload.(access.PrivateKeyPayload).Material.Reveal() != key.Material.Reveal() {
		t.Fatal("server key authority changed")
	}
	stop(t, s, store)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		t.Fatal("listener not released", err)
	}
	_ = l.Close()
}
func TestVLESSCreationValidationRollbackAndSurface(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, testfixture.Phase5)
	defer stop(t, s, store)
	plain := v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}
	d := vlessDoc(t, freePort(t), plain, "")
	var doc map[string]any
	_ = json.Unmarshal(d, &doc)
	invalid := []func(map[string]any){
		func(d map[string]any) { d["engine"] = "xray" }, func(d map[string]any) { d["users"].([]any)[0].(map[string]any)["uuid"] = "bad" },
		func(d map[string]any) { d["settings"].(map[string]any)["flow"] = "arbitrary" }, func(d map[string]any) { d["server_secret"] = map[string]any{"private_key": "bad"} },
	}
	for _, mutate := range invalid {
		var copy map[string]any
		_ = json.Unmarshal(d, &copy)
		mutate(copy)
		b, _ := json.Marshal(copy)
		if _, err := s.PlanCreation(ctx, "vless", b); err == nil {
			t.Fatal("invalid plan accepted")
		}
	}
	conflict, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conflict.Close()
	bad := vlessDoc(t, uint16(conflict.Addr().(*net.TCPAddr).Port), plain, "")
	p, err := s.PlanCreation(ctx, "vless", bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: bad, Digest: p.Digest, Revision: p.Revision}); err == nil {
		t.Fatal("port conflict committed")
	}
	state, _ := store.State(ctx)
	if state.Revision != 0 || state.PendingTransactions != 0 {
		t.Fatal("rollback authority")
	}
	a := applyVLESS(t, s, d)
	view, _ := s.Inbound(ctx, a.InboundID)
	if view.Health != "healthy" {
		t.Fatal("plain lifecycle")
	}
	tls := testkit.TLSForName(t, "vless.synthetic.test")
	tlsSettings := v.Settings{Security: v.TLS, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp", TLS: &tls}
	a = applyVLESS(t, s, vlessDoc(t, freePort(t), tlsSettings, ""))
	for _, request := range []application.ExportRequest{{Format: ports.Mihomo, ClientVersion: "1.19.30", BindingID: a.Bindings[0].BindingID}, {Format: ports.SingBox, ClientVersion: "1.14.1", BindingID: a.Bindings[0].BindingID}} {
		if _, err := s.ExportClient(ctx, a.InboundID, request); err != nil {
			t.Fatal("static TLS", err)
		}
	}
	if v.RealityCompiled {
		reality := v.Settings{Security: v.Reality, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Reality: &v.RealitySettings{ServerName: "target.test", Target: access.Endpoint{Host: "127.0.0.1", Port: freePort(t)}, ShortIDs: []v.ShortID{""}}}
		b := vlessDoc(t, freePort(t), reality, "")
		p, err := s.PlanCreation(ctx, "vless", b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: b, Digest: p.Digest, Revision: p.Revision}); err == nil {
			t.Fatal("unreachable target committed")
		}
		state, _ := store.State(ctx)
		if state.Revision != 2 || state.PendingTransactions != 0 {
			t.Fatal("target rollback")
		}
	}
}
func TestVLESSRuntimeFaultRollback(t *testing.T) {
	for _, stage := range []string{"compile", "start", "health"} {
		t.Run(stage, func(t *testing.T) {
			s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, testfixture.Phase5)
			defer stop(t, s, store)
			p, _, x, _ := testfixture.Phase5()
			h := &faultHandle{stage: stage}
			eng, _ := registry.NewEngines(faultEngine{stage: stage, handle: h})
			svc, err := application.New(store, p, eng, x, version.Current())
			if err != nil {
				t.Fatal(err)
			}
			if err := svc.EnableRuntime(context.Background()); err != nil {
				t.Fatal(err)
			}
			defer svc.CloseRuntime(context.Background())
			d := vlessDoc(t, freePort(t), v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, "")
			plan, err := svc.PlanCreation(context.Background(), "vless", d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ApplyCreation(context.Background(), "vless", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision}); err == nil {
				t.Fatal("fault committed")
			}
			state, _ := store.State(context.Background())
			if state.Revision != 0 || state.PendingTransactions != 0 || stage != "compile" && !h.closed {
				t.Fatal("fault cleanup")
			}
		})
	}
}
