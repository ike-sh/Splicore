//go:build splicore_xray_integration

package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

func pinnedEngine(t *testing.T, root string) *xray.Engine {
	t.Helper()
	binary := os.Getenv("SPLICORE_XRAY_BINARY")
	if binary == "" {
		t.Fatal("integration gate requires verified SPLICORE_XRAY_BINARY")
	}
	e := xray.New(xray.Options{BinaryPath: binary, RuntimeDirectory: root})
	if err := e.ValidateAvailability(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close(context.Background()) })
	return e
}
func TestXrayPinnedTransactionRecoveryAndSharedAccount(t *testing.T) {
	testXrayPinnedTransactionRecoveryAndSharedAccount(t, v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, "")
}

func testXrayPinnedTransactionRecoveryAndSharedAccount(t *testing.T, settings v.Settings, privateKey string) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	path := filepath.Join(root, "state", "state.db")
	runtimeRoot := filepath.Join(root, "runtime")
	e := pinnedEngine(t, runtimeRoot)
	s, store := setupProtocols(t, path, nil, composeXray(e))
	defer func() { stop(t, s, store) }()
	d := xrayDocument(t, vlessDoc(t, freePort(t), settings, privateKey))
	p, err := s.PlanCreation(ctx, "vless", d)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.Inbound(ctx, a.InboundID)
	if err != nil || view.Runtime == nil || view.Health != "healthy" || view.Inbound.Engine != "xray" {
		t.Fatal("runtime view", err)
	}
	old := *view.Runtime
	oldBindings := view.Bindings
	// A native placement binds the same Account-owned UUID credentials. SQLite
	// keeps its existing models; no second account or credential table is added.
	if s.CloseRuntime(ctx) != nil {
		t.Fatal("stop")
	}
	state, _ := store.State(ctx)
	native := view.Inbound
	native.ID, _ = identity.NewID()
	native.Engine = "native"
	native.Listeners = append([]access.Listener(nil), native.Listeners...)
	native.Listeners[0].ID, _ = identity.NewID()
	native.Listeners[0].Endpoint.Port = freePort(t)
	native.DisplayEndpoints = append([]access.DisplayEndpoint(nil), native.DisplayEndpoints...)
	native.DisplayEndpoints[0].ID, _ = identity.NewID()
	bindings, err := store.Bindings(ctx, a.InboundID)
	if err != nil {
		t.Fatal(err)
	}
	serverCredentials, err := store.RevealInboundCredentials(ctx, a.InboundID)
	if err != nil {
		t.Fatal(err)
	}
	actorID, _ := identity.NewID()
	_, err = store.Transact(ctx, state.Revision, identity.Actor{Principal: "test", RequestID: actorID}, func(w ports.Writer) error {
		if err := w.CreateInbound(native); err != nil {
			return err
		}
		for _, credential := range serverCredentials {
			credential.ID, _ = identity.NewID()
			credential.OwnerInboundID = &native.ID
			if err := w.CreateCredential(credential); err != nil {
				return err
			}
		}
		for _, b := range bindings {
			b.ID, _ = identity.NewID()
			b.InboundID = native.ID
			if err := w.CreateBinding(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal("same account/credential placement", err)
	}
	pReg, eReg, exports, err := composeXray(e)()
	if err != nil {
		t.Fatal(err)
	}
	s, err = application.New(store, pReg, eReg, exports, version.Current())
	if err != nil || s.EnableRuntime(ctx) != nil {
		t.Fatal("recovery", err)
	}
	view, err = s.Inbound(ctx, a.InboundID)
	if err != nil || view.Runtime.Generation == old.Generation || view.Runtime.PID == old.PID || len(view.Bindings) != 2 {
		t.Fatal("regeneration")
	}
	if _, err = os.Stat(old.ConfigArtifact); !os.IsNotExist(err) {
		t.Fatal("old config retained")
	}
	nativeView, err := s.Inbound(ctx, native.ID)
	if err != nil || nativeView.Health != "healthy" {
		t.Fatal("native placement", err)
	}
	for n, b := range view.Bindings {
		if b.AccountID != oldBindings[n].AccountID {
			t.Fatal("identity recovery")
		}
	}
	nativeBindings, err := store.Bindings(ctx, native.ID)
	if err != nil || len(nativeBindings) != len(bindings) {
		t.Fatal("native bindings", err)
	}
	byCredential := map[identity.ID]access.Binding{}
	for _, binding := range nativeBindings {
		byCredential[binding.CredentialID] = binding
	}
	for n, b := range bindings {
		c, err := store.RevealCredential(ctx, b.CredentialID)
		if err != nil {
			t.Fatal(err)
		}
		left, err := (v.Module{Security: settings.Security}).BuildClientProfile(ctx, ports.AuthorizedBinding{Inbound: view.Inbound, Binding: b, Credential: c})
		if err != nil {
			t.Fatal(err)
		}
		rightBinding, ok := byCredential[b.CredentialID]
		if !ok || rightBinding.AccountID != b.AccountID {
			t.Fatal("shared account and UUID credential")
		}
		right, err := (v.Module{Security: settings.Security}).BuildClientProfile(ctx, ports.AuthorizedBinding{Inbound: native, Binding: rightBinding, Credential: c})
		if err != nil {
			t.Fatal(err)
		}
		// Placement identity differs; public endpoint, UUID and security must match.
		right.ID = left.ID
		l, _ := json.Marshal(left)
		r, _ := json.Marshal(right)
		if string(l) != string(r) {
			t.Fatal("ClientProfile semantic difference")
		}
		if settings.Security == v.Reality {
			if left.TLS.RealityPublicKey == "" || left.TLS.RealityShortID != string(settings.Reality.ShortIDs[0]) || left.TLS.ServerName != settings.Reality.ServerName || strings.Contains(string(l), privateKey) {
				t.Fatal("REALITY public profile boundary")
			}
		}
		for _, target := range []ports.Format{ports.Mihomo, ports.SingBox, ports.URI} {
			exporter, _ := exports.Get(target)
			version := ""
			if target == ports.Mihomo {
				version = "1.19.30"
			}
			if target == ports.SingBox {
				version = "1.14.1"
			}
			l, le := exporter.Export(ctx, left, ports.ExportTarget{Format: target, ClientVersion: version})
			r, re := exporter.Export(ctx, right, ports.ExportTarget{Format: target, ClientVersion: version})
			if le != nil || re != nil || string(l) != string(r) {
				t.Fatal("shared exporter", n, target)
			}
		}
	}
	page, _ := s.Inbounds(ctx)
	b := view.Bindings[0]
	beforeReconcile := view.Runtime.Generation
	if _, err = s.SetBinding(ctx, a.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: false, ResourceRevision: b.Revision, Revision: page.Revision}); err != nil {
		t.Fatal("reconcile", err)
	}
	view, _ = s.Inbound(ctx, a.InboundID)
	if view.Runtime.Generation == beforeReconcile {
		t.Fatal("reconcile generation")
	}
	ordinary, _ := json.Marshal(view)
	if privateKey != "" && strings.Contains(string(ordinary), privateKey) {
		t.Fatal("ordinary private key leak")
	}
	for _, binding := range bindings {
		c, _ := store.RevealCredential(ctx, binding.CredentialID)
		if strings.Contains(string(ordinary), c.Payload.(access.UUIDPayload).UUID.Reveal()) {
			t.Fatal("ordinary secret leak")
		}
	}
	if strings.Contains(fmt.Sprint(view.Runtime), "synthetic-private-log") {
		t.Fatal("log leak")
	}
}
func TestXrayPinnedPortConflictRollback(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	e := pinnedEngine(t, filepath.Join(root, "runtime"))
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, composeXray(e))
	defer stop(t, s, store)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	d := xrayDocument(t, vlessDoc(t, uint16(listener.Addr().(*net.TCPAddr).Port), v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, ""))
	p, err := s.PlanCreation(ctx, "vless", d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision}); err == nil {
		t.Fatal("conflict accepted")
	}
	state, _ := store.State(ctx)
	inbounds, _ := store.Inbounds(ctx)
	if state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 {
		t.Fatal("rollback authority")
	}
}
