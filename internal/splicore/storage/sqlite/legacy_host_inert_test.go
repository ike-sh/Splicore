package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestLegacyHostSchemaInertAcrossUpgrades(t *testing.T) {
	for _, base := range []int{0, 6, 7, 8} {
		for _, mixed := range []bool{false, true} {
			name := "fresh"
			if base != 0 {
				name = migrations()[base-1].Name
			}
			if mixed {
				name += "-mixed"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				path := filepath.Join(t.TempDir(), "private", "state.db")
				if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if base > 0 {
					db, err := sql.Open("sqlite", path)
					if err != nil {
						t.Fatal(err)
					}
					if err = migrate(ctx, db, migrations()[:base]); err != nil {
						t.Fatal(err)
					}
					if base >= 7 && mixed {
						_, err = db.Exec(`UPDATE client_host_profiles SET document='{"system_proxy":{"enabled":true,"backend":"wininet","local_inbound":"00000000-0000-4000-8000-000000000001"}}'`)
						if err != nil {
							t.Fatal(err)
						}
					}
					if err = db.Close(); err != nil {
						t.Fatal(err)
					}
					if err = os.Chmod(path, 0600); err != nil {
						t.Fatal(err)
					}
				}
				s, err := Open(ctx, path, options(t))
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				var before string
				if err = s.db.QueryRow("SELECT document FROM client_host_profiles").Scan(&before); err != nil {
					t.Fatal(err)
				}
				// A trigger makes every accidental normal write a hard failure.
				if _, err = s.db.Exec(`CREATE TRIGGER no_legacy_host_write BEFORE UPDATE ON client_host_profiles BEGIN SELECT RAISE(ABORT,'legacy table is inert'); END`); err != nil {
					t.Fatal(err)
				}
				state, err := s.ClientState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				state.Enabled = false
				state.LocalInbounds = []client.LocalInbound{{ID: newID(t), Name: "preserved Core TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore0", Addresses: []string{"198.18.0.1/30"}, MTU: 1500, Stack: "gvisor"}}}
				if _, err = s.Transact(ctx, state.Revision, actor(t), func(w ports.Writer) error { return w.(ports.ClientWriter).ReplaceClient(state, nil) }); err != nil {
					t.Fatal(err)
				}
				var after string
				if err = s.db.QueryRow("SELECT document FROM client_host_profiles").Scan(&after); err != nil || after != before {
					t.Fatal("historical data modified", err)
				}
				got, err := s.ClientState(ctx)
				if err != nil || len(got.LocalInbounds) != 1 || got.LocalInbounds[0].TUN.Interface != "splicore0" {
					t.Fatal("TUN lost", err)
				}
				wire, _ := json.Marshal(got)
				if strings.Contains(string(wire), "host_integration") || strings.Contains(string(wire), "system_proxy") {
					t.Fatal("deprecated state exported as config")
				}
				if err = s.Close(); err != nil {
					t.Fatal(err)
				}
				backup := filepath.Join(filepath.Dir(path), "backup.db")
				if _, err = MaintenanceBackup(ctx, path, backup); err != nil {
					t.Fatal(err)
				}
				restored, err := Open(ctx, backup, options(t))
				if err != nil {
					t.Fatal(err)
				}
				defer restored.Close()
				var legacy string
				if err = restored.db.QueryRow("SELECT document FROM client_host_profiles").Scan(&legacy); err != nil || legacy != before {
					t.Fatal("backup lost inert history", err)
				}
				back, err := restored.ClientState(ctx)
				if err != nil || back.Enabled || len(back.LocalInbounds) != 1 {
					t.Fatal("backup reactivated legacy or lost Core", err)
				}
			})
		}
	}
}
