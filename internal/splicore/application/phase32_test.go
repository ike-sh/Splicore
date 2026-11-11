package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	dc "github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func TestPhase32EncryptedPersistenceMultiUserAndRedaction(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupProtocols(t, path, nil, registry.NativeCore)
	defer func() { stop(t, s, store) }()
	decryption, public, e := encryption.Generate("mlkem768", "random", "0rtt", "600s", "100-35-35")
	if e != nil {
		t.Fatal(e)
	}
	settings := vl.Settings{Security: vl.Plain, Flow: vl.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}
	port := freePort(t)
	destination := echoTarget(t, "127.0.0.1")
	var document map[string]any
	_ = json.Unmarshal(vlessDoc(t, port, settings, ""), &document)
	document["server_secret"] = map[string]any{"decryption": decryption}
	data, _ := json.Marshal(document)
	created := applyVLESS(t, s, data)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	check := func() {
		t.Helper()
		view, e := client.Inbound(ctx, created.InboundID)
		if e != nil || view.Health != "healthy" {
			t.Fatal("inbound health", e)
		}
		secrets, e := store.RevealInboundCredentials(ctx, created.InboundID)
		if e != nil || len(secrets) != 1 || secrets[0].Payload.(access.PrivateKeyPayload).Material.Reveal() != decryption {
			t.Fatal("encrypted inbound credential")
		}
		diagnostics, _ := s.Doctor(ctx, "test")
		b, _ := json.Marshal([]any{view, diagnostics, secrets})
		if strings.Contains(string(b), decryption) || strings.Contains(fmt.Sprintf("%+v %#v", secrets, secrets), decryption) {
			t.Fatal("secret disclosure")
		}
		for index, binding := range created.Bindings {
			payload := expansionCredential(t, store, created, index)
			nodeID, _ := identity.NewID()
			credentialID, _ := identity.NewID()
			credential := access.Credential{ID: credentialID, OwnerNodeID: &nodeID, Kind: access.UUID, Schema: 1, State: "active", Payload: payload, Stamp: identity.NewStamp(time.Now())}
			options, _ := json.Marshal(vl.ClientOptions{Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp", Encryption: public})
			node := dc.RemoteNode{ID: nodeID, Name: "persisted user", CredentialID: credentialID, Protocol: vl.Key(vl.Plain), Endpoint: access.Endpoint{Host: "127.0.0.1", Port: port}, Transport: cfg.Config{Kind: "tcp"}, Security: dc.Security{Kind: "none"}, Options: dc.Options{Schema: 1, Data: options}}
			dialer, e := (native.VLESSOutboundFactory{}).Build(ctx, node, credential)
			if e != nil {
				t.Fatal(e)
			}
			for range 2 {
				conn, e := dialer.DialContext(ctx, destination)
				if e != nil {
					dialer.Close()
					t.Fatal(e)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				message := []byte("persisted encrypted user traffic")
				_, e = conn.Write(message)
				got := make([]byte, len(message))
				if e == nil {
					_, e = io.ReadFull(conn, got)
				}
				conn.Close()
				if e != nil || string(got) != string(message) {
					dialer.Close()
					t.Fatal("persisted traffic", e)
				}
			}
			dialer.Close()
			exported, e := client.ExportClient(ctx, created.InboundID, application.ExportRequest{Format: ports.Xray, ClientVersion: "26.10.21", BindingID: binding.BindingID})
			if e != nil {
				t.Fatal(e)
			}
			if !strings.Contains(exported.Content, public) || strings.Contains(exported.Content, decryption) {
				t.Fatal("public config projection")
			}
			if _, e = client.ExportClient(ctx, created.InboundID, application.ExportRequest{Format: ports.Mihomo, ClientVersion: "1.19.30", BindingID: binding.BindingID}); e == nil {
				t.Fatal("unqualified export silently lost encryption")
			}
		}
	}
	check()
	server.Close()
	stop(t, s, store)
	raw, e := os.ReadFile(path)
	if e != nil || strings.Contains(string(raw), decryption) {
		t.Fatal("plaintext credential at rest")
	}
	s, store = setupProtocols(t, path, nil, registry.NativeCore)
	server = httptest.NewServer(api.Handler(s))
	defer server.Close()
	client = transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	check()
}
