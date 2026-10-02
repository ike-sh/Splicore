package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

func TestClientSharedPortFiltersBeforeDecrypt(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	state, _ := s.State(ctx)
	stamp := identity.NewStamp(time.Now())
	inbound := func() access.Inbound {
		return access.Inbound{ID: newID(t), NodeID: state.NodeID, Name: "fixture", Protocol: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}, Engine: "native", Listeners: []access.Listener{{ID: newID(t), Transport: "tcp", Endpoint: access.Endpoint{Host: "192.0.2.1", Port: 443}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(t), Endpoint: access.Endpoint{Host: "example.com", Port: 443}}}, Settings: access.Settings{Schema: 1, Data: []byte(`{}`)}, Stamp: stamp}
	}
	a, b := inbound(), inbound()
	key, _, err := v.GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	shared := access.Credential{ID: newID(t), OwnerInboundID: &a.ID, Kind: access.Password, Schema: 1, State: "active", Payload: access.PasswordPayload{Password: secret.New("synthetic-shared-password")}, Stamp: stamp}
	private := access.Credential{ID: newID(t), OwnerInboundID: &a.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: key, Stamp: stamp}
	other := shared
	other.ID = newID(t)
	other.OwnerInboundID = &b.ID
	if _, err = s.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		for _, i := range []access.Inbound{a, b} {
			if err := w.CreateInbound(i); err != nil {
				return err
			}
		}
		for _, c := range []access.Credential{shared, private, other} {
			if err := w.CreateCredential(c); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Corrupt excluded rows: success proves they were never decrypted.
	if _, err = s.db.Exec("UPDATE credentials SET ciphertext=zeroblob(32) WHERE id IN (?,?)", private.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.RevealClientSharedCredentials(ctx, a.ID)
	if err != nil || len(got) != 1 || got[0].ID != shared.ID {
		t.Fatal("client port decrypted an excluded owner or private key", err)
	}
	if _, err = s.RevealCredential(ctx, private.ID); !codeIs(err, identity.Corrupt) {
		t.Fatal("corruption fixture was ineffective")
	}
}
