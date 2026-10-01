package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	tm "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"github.com/sagernet/sing-box/internal/splicore/tlsconfig"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupTUIC(t *testing.T, path string, wrap func(ports.MultiBindingRepository) ports.Repository) (*application.Service, *sqlite.Store) {
	return setupProtocols(t, path, wrap, registry.Phase4)
}
func tuDoc(t *testing.T, port uint16, tls tlsconfig.Settings) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{"schema": 1, "name": "synthetic-tuic", "listener": access.Endpoint{Host: "127.0.0.1", Port: port}, "display_endpoint": access.Endpoint{Host: "localhost", Port: port}, "settings": tm.Settings{TLS: tls, Version: 5, CongestionControl: "cubic", UDPRelayMode: "native"}, "policy_mode": "metadata_only", "users": []any{map[string]any{"account_name": "Alice", "uuid": "68f4f564-142b-46b3-8c89-322a37ef1b30", "password": "SyntheticAlicePasswordPhase3", "traffic_policy": map[string]any{"quota_bytes": 1000, "upload_bps": 2000}}, map[string]any{"account_name": "Bob", "traffic_policy": map[string]any{"quota_bytes": 5000, "download_bps": 9000}}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func applyTUIC(t *testing.T, s *application.Service, d json.RawMessage) application.CreationResult {
	t.Helper()
	p, err := s.PlanCreation(context.Background(), "tuic", d)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.ApplyCreation(context.Background(), "tuic", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestTUICAPIMultiBindingRecoveryAndIsolation(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupTUIC(t, path, nil)
	defer func() { stop(t, s, store) }()
	tls := testkit.TLSForName(t, "tuic.synthetic.test")
	port := udpPort(t)
	d := tuDoc(t, port, tls)
	server := httptest.NewServer(api.Handler(s))
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	plan, e := client.PlanCreation(ctx, "tuic", d)
	if e != nil {
		t.Fatal(e)
	}
	a, e := client.ApplyCreation(ctx, "tuic", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision})
	if e != nil || len(a.Bindings) != 2 {
		t.Fatal("multi-user apply", e)
	}
	view, e := client.Inbound(ctx, a.InboundID)
	if e != nil || view.Health != "healthy" || len(view.Bindings) != 2 {
		t.Fatal("view", e)
	}
	metadata, _ := json.Marshal(view)
	var fields map[string]json.RawMessage
	if json.Unmarshal(metadata, &fields) != nil || fields["binding_id"] != nil || fields["account_id"] != nil {
		t.Fatal("multi-user view contains legacy single-binding IDs")
	}
	if strings.Contains(string(metadata), "SyntheticAlicePasswordPhase3") || strings.Contains(string(metadata), "PRIVATE KEY") {
		t.Fatal("secret metadata")
	}
	if _, e = client.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1"}); e == nil {
		t.Fatal("ambiguous user export admitted")
	}
	for _, b := range view.Bindings {
		if b.PolicyID == nil || b.PolicyEnforced {
			t.Fatal("policy semantics")
		}
		exp, e := client.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1", BindingID: b.BindingID})
		if e != nil {
			t.Fatal(e)
		}
		var out map[string]any
		if json.Unmarshal([]byte(exp.Content), &out) != nil || out["password"] == "" || out["server"] != "localhost" {
			t.Fatal("password export")
		}
		if strings.Contains(exp.Content, tls.PrivateKeyFile) || strings.Contains(exp.Content, "quota") || strings.Contains(exp.Content, "upload_bps") {
			t.Fatal("runtime/policy polluted client")
		}
	}
	page, _ := s.Inbounds(ctx)
	b := view.Bindings[0]
	if _, e = client.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: b.Revision, Revision: page.Revision}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1", BindingID: b.BindingID}); e == nil {
		t.Fatal("disabled export admitted")
	}
	item, _ := s.Inbound(ctx, a.InboundID)
	page, _ = s.Inbounds(ctx)
	if _, e = s.SetDisplay(ctx, a.InboundID, application.DisplayRequest{Endpoint: access.Endpoint{Host: "::1", Port: port}, ResourceRevision: item.Inbound.Revision, Revision: page.Revision}); e != nil {
		t.Fatal(e)
	}
	server.Close()
	stop(t, s, store)
	assertUDPReleased(t, port)
	s, store = setupTUIC(t, path, nil)
	recovered, e := s.Inbound(ctx, a.InboundID)
	if e != nil || recovered.Health != "healthy" || recovered.Inbound.DisplayEndpoints[0].Endpoint.Host != "::1" {
		t.Fatal("SQLite recovery", e)
	}
	for _, v := range recovered.Bindings {
		if v.BindingID == b.BindingID && v.Enabled {
			t.Fatal("disabled binding resurrected")
		}
	}
	page, _ = s.Inbounds(ctx)
	for _, v := range recovered.Bindings {
		if v.BindingID == b.BindingID {
			if _, e = s.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: true, ResourceRevision: v.Revision, Revision: page.Revision}); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e = s.ExportClient(ctx, a.InboundID, application.ExportRequest{Format: ports.Surge, ClientVersion: "6.7.0", BindingID: b.BindingID}); e == nil {
		t.Fatal("unsupported Surge export")
	}
}

func TestTUICCreationRollbackTLSAndUDPConflict(t *testing.T) {
	for _, mode := range []string{"port", "bad-key", "bad-cert", "wrong-identity", "trust", "storage"} {
		t.Run(mode, func(t *testing.T) {
			port := udpPort(t)
			tls := testkit.TLSForName(t, "tuic.synthetic.test")
			var occupied net.PacketConn
			if mode == "port" {
				var e error
				occupied, e = net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
				if e != nil {
					t.Fatal(e)
				}
				defer occupied.Close()
			}
			if mode == "bad-key" {
				if e := os.WriteFile(tls.PrivateKeyFile, []byte("synthetic invalid key"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "bad-cert" {
				if e := os.WriteFile(tls.CertificateFile, []byte("synthetic invalid certificate"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "wrong-identity" {
				tls.ServerName = "wrong.synthetic.test"
			}
			if mode == "trust" {
				tls.CACertificate = testkit.TLSForName(t, "tuic.synthetic.test").CACertificate
			}
			var fault *hyCommitFault
			var wrap func(ports.MultiBindingRepository) ports.Repository
			if mode == "storage" {
				wrap = func(r ports.MultiBindingRepository) ports.Repository {
					fault = &hyCommitFault{MultiBindingRepository: r, fail: true}
					return fault
				}
			}
			s, store := setupTUIC(t, filepath.Join(t.TempDir(), "state", "state.db"), wrap)
			defer stop(t, s, store)
			d := tuDoc(t, port, tls)
			p, e := s.PlanCreation(context.Background(), "tuic", d)
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.ApplyCreation(context.Background(), "tuic", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
			if e == nil {
				t.Fatal("failed candidate committed")
			}
			if mode == "port" {
				var de *identity.Error
				if !errors.As(e, &de) || de.Code != identity.PortConflict {
					t.Fatal("UDP conflict not typed", e)
				}
			}
			state, _ := store.State(context.Background())
			all, _ := store.Inbounds(context.Background())
			if state.Revision != 0 || state.PendingTransactions != 0 || len(all) != 0 {
				t.Fatal("failed transaction visible")
			}
			if mode != "port" {
				assertUDPReleased(t, port)
			}
		})
	}
}

func TestTUICReplacementRollbackAndInterruptedJournal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	var fault *hyCommitFault
	s, store := setupTUIC(t, path, func(r ports.MultiBindingRepository) ports.Repository {
		fault = &hyCommitFault{MultiBindingRepository: r}
		return fault
	})
	defer func() { stop(t, s, store) }()
	a := applyTUIC(t, s, tuDoc(t, udpPort(t), testkit.TLSForName(t, "tuic.synthetic.test")))
	fault.fail = true
	b := a.Bindings[0]
	if _, e := s.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: 1, Revision: 1}); e == nil {
		t.Fatal("replacement fault accepted")
	}
	view, e := s.Inbound(ctx, a.InboundID)
	state, _ := store.State(ctx)
	if e != nil || view.Health != "healthy" || state.Revision != 1 || state.PendingTransactions != 0 {
		t.Fatal("old runtime not restored", e)
	}
	for _, v := range view.Bindings {
		if !v.Enabled {
			t.Fatal("rollback mutated bindings")
		}
	}
	request, _ := identity.NewID()
	if _, e = store.BeginRuntimeOperation(ctx, 1, identity.Actor{Principal: "synthetic", RequestID: request}, "runtime_replace"); e != nil {
		t.Fatal(e)
	}
	stop(t, s, store)
	s, store = setupTUIC(t, path, nil)
	state, _ = store.State(ctx)
	if state.PendingTransactions != 0 || state.Revision != 1 {
		t.Fatal("pending recovery")
	}
}

func TestTUICStartupFaults(t *testing.T) {
	for _, stage := range []string{"compile", "start", "health"} {
		t.Run(stage, func(t *testing.T) {
			s, store := setupTUIC(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
			defer stop(t, s, store)
			p, _, x, _ := registry.Phase4()
			h := &faultHandle{stage: stage}
			eng, _ := registry.NewEngines(faultEngine{stage: stage, handle: h})
			svc, e := application.New(store, p, eng, x, version.Current())
			if e != nil {
				t.Fatal(e)
			}
			if e = svc.EnableRuntime(context.Background()); e != nil {
				t.Fatal(e)
			}
			defer svc.CloseRuntime(context.Background())
			d := tuDoc(t, udpPort(t), testkit.TLSForName(t, "tuic.synthetic.test"))
			plan, e := svc.PlanCreation(context.Background(), "tuic", d)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = svc.ApplyCreation(context.Background(), "tuic", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision}); e == nil {
				t.Fatal("startup fault committed")
			}
			state, _ := store.State(context.Background())
			if state.Revision != 0 || state.PendingTransactions != 0 || stage != "compile" && !h.closed {
				t.Fatal("startup cleanup")
			}
		})
	}
}

func TestTUICStrictInputAndSecretRedaction(t *testing.T) {
	d := tuDoc(t, udpPort(t), testkit.TLSForName(t, "tuic.synthetic.test"))
	for _, password := range []string{`null`, `""`, `"short"`, `123`, `[]`} {
		b := strings.Replace(string(d), `"SyntheticAlicePasswordPhase3"`, password, 1)
		if _, e := (tm.Module{}).DecodeCreation([]byte(b)); e == nil {
			t.Fatal("invalid password accepted")
		}
	}
	for _, b := range []string{strings.Replace(string(d), `"account_name":"Alice"`, `"account_name":"Alice","account_enabled":null`, 1), strings.Replace(string(d), `"account_name":"Alice"`, `"account_name":"Alice","enabled":null`, 1), strings.Replace(string(d), `"zero_rtt_handshake":false`, `"zero_rtt_handshake":null`, 1), strings.Replace(string(d), `"68f4f564-142b-46b3-8c89-322a37ef1b30"`, `"invalid-uuid"`, 1), strings.Replace(string(d), `"account_name":"Bob"`, `"account_name":"Alice"`, 1), strings.Replace(string(d), `"account_name":"Bob"`, `"account_name":"Bob","password":"SyntheticAlicePasswordPhase3"`, 1), strings.Replace(string(d), `"metadata_only"`, `"enforced"`, 1), strings.Replace(string(d), `"schema":1`, `"schema":1,"schema":1`, 1)} {
		if _, e := (tm.Module{}).DecodeCreation([]byte(b)); e == nil {
			t.Fatal("invalid document accepted")
		}
	}
	decoded, e := (tm.Module{}).DecodeCreation(d)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(fmt.Sprintf("%+v", decoded), "SyntheticAlicePasswordPhase3") {
		t.Fatal("document formatting leaked")
	}
}
