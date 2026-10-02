package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/policy"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	sm "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSchema2And3ToCurrentPreservePopulatedSnellStateCiphertextAndConstraints(t *testing.T) {
	for _, from := range []int{2, 3, 4} {
		t.Run(fmt.Sprint(from), func(t *testing.T) { testPopulatedForwardMigration(t, from) })
	}
}
func testPopulatedForwardMigration(t *testing.T, from int) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "state.db")
	db, e := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)")
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if e = migrate(ctx, db, migrations()[:from]); e != nil {
		t.Fatal(e)
	}
	opts := options(t)
	opts.ValidateInbound = (sm.Module{Version: 5}).ValidateInbound
	opts.CredentialKinds = func(k access.ProtocolKey) ([]access.CredentialKind, error) {
		return []access.CredentialKind{access.PSK}, nil
	}
	old := &Store{db: db, options: opts}
	var node identity.ID
	if e = db.QueryRow("SELECT id FROM nodes").Scan(&node); e != nil {
		t.Fatal(e)
	}
	stamp := identity.NewStamp(time.Now())
	a := account(t)
	i := access.Inbound{ID: newID(t), NodeID: node, Name: "schema2 Snell", Protocol: sm.Key(5), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: newID(t), Transport: "tcp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 23456}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: newID(t), Endpoint: access.Endpoint{Host: "example.test", Port: 23456}}}, Settings: access.Settings{Schema: 1, Data: []byte(`{"version":5}`)}, Stamp: stamp}
	c := access.Credential{ID: newID(t), OwnerAccountID: &a.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: secret.New("SyntheticMigrationPSKSchema2")}, Stamp: stamp}
	quota := int64(1234)
	p := policy.TrafficPolicy{ID: newID(t), QuotaBytes: &quota, Stamp: stamp}
	b := access.Binding{ID: newID(t), AccountID: a.ID, InboundID: i.ID, CredentialID: c.ID, Enabled: true, PolicyOverrideID: &p.ID, Stamp: stamp}
	op, e := old.Transact(ctx, 0, actor(t), func(w ports.Writer) error {
		if e := w.CreateAccount(a); e != nil {
			return e
		}
		if e := w.CreateInbound(i); e != nil {
			return e
		}
		if e := w.CreateCredential(c); e != nil {
			return e
		}
		if e := w.CreatePolicy(p); e != nil {
			return e
		}
		return w.CreateBinding(b)
	})
	if e != nil {
		t.Fatal(e)
	}
	var before []byte
	if e = db.QueryRow("SELECT ciphertext FROM credentials WHERE id=?", c.ID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	migrated, e := Open(ctx, path, opts)
	if e != nil {
		t.Fatal("populated migration", e)
	}
	defer migrated.Close()
	state, e := migrated.State(ctx)
	if e != nil || state.Schema != len(migrations()) || state.NodeID != node || state.Revision != 1 || state.PendingTransactions != 0 {
		t.Fatal("authority changed", e)
	}
	var after []byte
	if e = migrated.db.QueryRow("SELECT ciphertext FROM credentials WHERE id=?", c.ID).Scan(&after); e != nil || !bytes.Equal(before, after) {
		t.Fatal("ciphertext changed", e)
	}
	revealed, e := migrated.RevealCredential(ctx, c.ID)
	if e != nil || revealed.Payload.(access.PSKPayload).Key.Reveal() != c.Payload.(access.PSKPayload).Key.Reveal() {
		t.Fatal("AAD/decryption changed", e)
	}
	bound, e := migrated.Binding(ctx, i.ID)
	if e != nil || bound.ID != b.ID || bound.PolicyOverrideID == nil || *bound.PolicyOverrideID != p.ID {
		t.Fatal("bindings lost", e)
	}
	var q int64
	var txState string
	if e = migrated.db.QueryRow("SELECT quota_bytes FROM traffic_policies WHERE id=?", p.ID).Scan(&q); e != nil || q != quota {
		t.Fatal("policy lost", e)
	}
	if e = migrated.db.QueryRow("SELECT state FROM transactions WHERE id=?", op.ID).Scan(&txState); e != nil || txState != "committed" {
		t.Fatal("journal lost", e)
	}
	other := account(t)
	otherCred := c
	otherCred.ID = newID(t)
	otherCred.OwnerAccountID = &other.ID
	second := b
	second.ID = newID(t)
	second.AccountID = other.ID
	second.CredentialID = otherCred.ID
	if _, e = migrated.Transact(ctx, 1, actor(t), func(w ports.Writer) error {
		if e := w.CreateAccount(other); e != nil {
			return e
		}
		if e := w.CreateCredential(otherCred); e != nil {
			return e
		}
		return w.CreateBinding(second)
	}); !codeIs(e, identity.Invalid) {
		t.Fatal("Snell single-binding constraint lost", e)
	}
	password := c
	password.ID = newID(t)
	password.Kind = access.Password
	password.Payload = access.PasswordPayload{Password: secret.New("SyntheticPasswordSchema3")}
	if _, e = migrated.Transact(ctx, 1, actor(t), func(w ports.Writer) error { return w.CreateCredential(password) }); e != nil {
		t.Fatal("password kind not migrated", e)
	}
	revealed, e = migrated.RevealCredential(ctx, password.ID)
	if e != nil || revealed.Payload.(access.PasswordPayload).Password.Reveal() != "SyntheticPasswordSchema3" {
		t.Fatal("password encrypted roundtrip", e)
	}
	if _, e = migrated.db.Exec("UPDATE credentials SET kind='unknown' WHERE id=?", password.ID); e == nil {
		t.Fatal("kind CHECK lost")
	}
	if _, e = migrated.db.Exec("UPDATE bindings SET credential_id=? WHERE id=?", newID(t), b.ID); e == nil {
		t.Fatal("foreign key lost")
	}
	if e = integrity(ctx, migrated.db); e != nil {
		t.Fatal(e)
	}
	server := access.Credential{ID: newID(t), OwnerInboundID: &i.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: access.PrivateKeyPayload{Algorithm: "x25519", Material: secret.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, Stamp: stamp}
	if _, e = migrated.Transact(ctx, 2, actor(t), func(w ports.Writer) error { return w.CreateCredential(server) }); e != nil {
		t.Fatal("generic server key kind", e)
	}
	serverKeys, e := migrated.RevealInboundCredentials(ctx, i.ID)
	if e != nil || len(serverKeys) != 1 || serverKeys[0].Payload.(access.PrivateKeyPayload).Material.Reveal() != server.Payload.(access.PrivateKeyPayload).Material.Reveal() {
		t.Fatal("owner-bound server key roundtrip")
	}
	for _, suffix := range []string{"", "-wal"} {
		data, _ := os.ReadFile(path + suffix)
		if bytes.Contains(data, []byte("SyntheticPasswordSchema3")) || bytes.Contains(data, []byte("SyntheticMigrationPSKSchema2")) {
			t.Fatal("plaintext in SQLite")
		}
	}
}
