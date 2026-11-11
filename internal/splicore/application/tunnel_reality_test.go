//go:build with_utls

package application_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	v "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestRealityGuardSQLiteStartupOrder(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupProtocols(t, path, nil, registry.NativeCore)
	enableClient(t, s)
	defer func() { stop(t, s, store) }()
	id := networkID(t)
	guard := client.LocalInbound{ID: id, Name: "REALITY prerequisite", Kind: "tunnel", Listen: access.Endpoint{Host: "127.0.0.1", Port: freePort(t)}, Tunnel: &client.TunnelSettings{Target: echoTarget(t, "127.0.0.1"), Network: "tcp"}, Sniffing: &client.SniffingPolicy{Enabled: true, Protocols: []string{"tls"}, RouteOnly: true}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &guard})
	routes := P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{ID: networkID(t), Name: "allow", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}, SniffedDomains: []string{"www.3verge.com"}}, Action: P.Action{Kind: P.Direct}}, {ID: networkID(t), Name: "deny", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}}, Action: P.Action{Kind: P.Reject}}}}}
	applyNetwork(t, s, routes)
	settings := v.Settings{Security: v.Reality, Flow: v.Vision, Transport: "tcp", PacketEncoding: "xudp", Reality: &v.RealitySettings{ServerName: "www.3verge.com", Target: guard.Listen, ShortIDs: []v.ShortID{"abcd"}}}
	created := applyVLESS(t, s, vlessDoc(t, freePort(t), settings, ""))
	stop(t, s, store)
	p, e, x, err := registry.NativeCore()
	if err != nil {
		t.Fatal(err)
	}
	vault, _ := secretvault.New("test", make([]byte, 32))
	store, err = sqlite.Open(ctx, path, sqlite.Options{Cipher: vault, ValidateInbound: func(i access.Inbound) error {
		m, e := p.Get(i.Protocol)
		if e != nil {
			return e
		}
		return m.ValidateInbound(i)
	}, CredentialKinds: func(k access.ProtocolKey) ([]access.CredentialKind, error) {
		m, e := p.Get(k)
		if e != nil {
			return nil, e
		}
		return m.Metadata().CredentialKinds, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err = application.New(store, p, e, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	outbounds, _ := registry.NewOutbounds()
	// This is the same composition used by app.Serve. Starting the server first
	// would fail its REALITY destination probe because no guard owns the port.
	if err = s.EnableRuntimeWithClient(ctx, outbounds); err != nil {
		t.Fatal("local prerequisite was restored too late", err)
	}
	view, err := s.Inbound(ctx, created.InboundID)
	if err != nil || view.Health != "healthy" {
		t.Fatal("protected REALITY failed to restore", view.Health, err)
	}
	status, err := s.ClientStatus(ctx)
	if err != nil || status.Health != "healthy" || status.State.LocalInbounds[0].ID != id {
		t.Fatal("guard failed to restore", err)
	}
}
