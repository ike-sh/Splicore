package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"os"
	"path/filepath"
	"testing"
)

func TestNetworkSchemaFiveMigrationPersistenceAndCorruptionDefense(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", "state.db")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, db, migrations()[:5]); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	state, err := s.ClientState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	group := newID(t)
	direct := P.Action{Kind: P.Direct}
	state.Network = P.Config{Groups: []P.PolicyGroup{{ID: group, Name: "persistent", Type: "selector", Members: []P.Action{direct}, Selector: &P.SelectorSettings{Selected: direct}}}, Route: P.RouteProfile{Final: &P.Action{Kind: P.Group, ID: group}}}
	op, err := s.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.(ports.ClientWriter).ReplaceClient(state, nil) })
	if err != nil || op.State != identity.Committed {
		t.Fatal(op, err)
	}
	s.Close()
	s, err = Open(ctx, path, options(t))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := s.ClientState(ctx)
	if err != nil || restored.Network.Groups[0].Selector.Selected != direct || restored.Network.Route.Final.ID != group {
		t.Fatal("SQLite not authority", err)
	}
	good, _ := json.Marshal(restored.Network)
	for _, document := range []string{"{\"unknown\":true}", "{\"route\":{},\"route\":{}}", "{\"route\":{\"final\":{\"kind\":\"group\",\"id\":\"00000000-0000-4000-8000-000000000001\"}}}"} {
		if _, err = s.db.Exec("UPDATE client_network_profiles SET document=?", document); err != nil {
			t.Fatal(err)
		}
		if _, err = s.ClientState(ctx); !codeIs(err, identity.Corrupt) {
			t.Fatal("corrupt state accepted", err)
		}
		var unchanged string
		if err = s.db.QueryRow("SELECT document FROM client_network_profiles").Scan(&unchanged); err != nil || unchanged != document {
			t.Fatal("corrupt user data deleted", err)
		}
	}
	if _, err = s.db.Exec("UPDATE client_network_profiles SET document=?", string(good)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ClientState(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.db.QueryRow("SELECT count(*) FROM schema_migrations").Scan(&count); err != nil || count != len(migrations()) {
		t.Fatal(count, err)
	}
	// A failed candidate write rolls back the aggregate along with the existing revision.
	before := restored.Revision
	bad := restored.Clone()
	bad.Network.Groups[0].Name = "not committed"
	_, err = s.Transact(ctx, before, actor(t), func(w ports.Writer) error {
		if err := w.(ports.ClientWriter).ReplaceClient(bad, nil); err != nil {
			return err
		}
		return identity.Err(identity.Unavailable, "synthetic rollback")
	})
	if err == nil {
		t.Fatal("rollback did not fail")
	}
	after, err := s.ClientState(ctx)
	if err != nil || after.Revision != before || after.Network.Groups[0].Name != "persistent" {
		t.Fatal("aggregate escaped transaction", err)
	}
}
