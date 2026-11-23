package distribution

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePrivateFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeWitnessPreflightRequiresExplicitLegacyBaseline(t *testing.T) {
	database := filepath.Join(t.TempDir(), "state.db")
	if err := upgradeWitnessPreflight(database); err != nil {
		t.Fatal("absent database rejected", err)
	}
	writePrivateFixture(t, database, "legacy-db")
	if err := upgradeWitnessPreflight(database); err == nil || !strings.Contains(err.Error(), "establish-witness --acknowledge-current-state") {
		t.Fatal("legacy database did not receive an executable diagnostic", err)
	}
	writePrivateFixture(t, database+".witness", "witness")
	if err := upgradeWitnessPreflight(database); err != nil {
		t.Fatal("witnessed database rejected before verified snapshot", err)
	}
}

func TestRestoreDatabaseGenerationRestoresOrRemovesWitnessAsOneGeneration(t *testing.T) {
	for _, witnessed := range []bool{false, true} {
		name := "legacy"
		if witnessed {
			name = "witnessed"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			backup, state := filepath.Join(root, "backup"), filepath.Join(root, "state")
			if err := os.MkdirAll(backup, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(state, 0700); err != nil {
				t.Fatal(err)
			}
			writePrivateFixture(t, filepath.Join(backup, "master.key"), "old-key")
			writePrivateFixture(t, filepath.Join(backup, "state.db"), "old-db")
			if witnessed {
				writePrivateFixture(t, filepath.Join(backup, "state.db.witness"), "old-witness")
			}
			writePrivateFixture(t, filepath.Join(state, "master.key"), "candidate-key")
			writePrivateFixture(t, filepath.Join(state, "state.db"), "candidate-db")
			for _, suffix := range []string{"-wal", "-shm", ".witness", ".witness.pending"} {
				writePrivateFixture(t, filepath.Join(state, "state.db")+suffix, "candidate-sidecar")
			}
			if err := restoreDatabaseGeneration(backup, state, os.Geteuid(), os.Getegid()); err != nil {
				t.Fatal(err)
			}
			for file, want := range map[string]string{"master.key": "old-key", "state.db": "old-db"} {
				got, err := os.ReadFile(filepath.Join(state, file))
				if err != nil || string(got) != want {
					t.Fatalf("%s was not restored: %q %v", file, got, err)
				}
			}
			for _, suffix := range []string{"-wal", "-shm", ".witness.pending"} {
				if _, err := os.Lstat(filepath.Join(state, "state.db") + suffix); !os.IsNotExist(err) {
					t.Fatalf("candidate sidecar %s survived: %v", suffix, err)
				}
			}
			got, err := os.ReadFile(filepath.Join(state, "state.db.witness"))
			if witnessed {
				if err != nil || string(got) != "old-witness" {
					t.Fatal("matching witness was not restored", string(got), err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("candidate witness survived legacy rollback", err)
			}
		})
	}
}

func TestRestoreDatabaseGenerationRejectsPendingBackupBeforeMutation(t *testing.T) {
	root := t.TempDir()
	backup, state := filepath.Join(root, "backup"), filepath.Join(root, "state")
	if err := os.MkdirAll(backup, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	for file, value := range map[string]string{"master.key": "old-key", "state.db": "old-db", "state.db.witness.pending": "pending"} {
		writePrivateFixture(t, filepath.Join(backup, file), value)
	}
	writePrivateFixture(t, filepath.Join(state, "master.key"), "candidate-key")
	writePrivateFixture(t, filepath.Join(state, "state.db"), "candidate-db")
	if err := restoreDatabaseGeneration(backup, state, os.Geteuid(), os.Getegid()); err == nil {
		t.Fatal("pending backup generation accepted")
	}
	for file, want := range map[string]string{"master.key": "candidate-key", "state.db": "candidate-db"} {
		got, err := os.ReadFile(filepath.Join(state, file))
		if err != nil || string(got) != want {
			t.Fatalf("live %s changed before backup validation: %q %v", file, got, err)
		}
	}
}
