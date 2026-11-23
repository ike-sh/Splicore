package sqlite

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestReadOnlyInspectionPreservesDatabaseWALSHMAndWitness(t *testing.T) {
	ctx := context.Background()
	source := filepath.Join(t.TempDir(), "source", "state.db")
	store, err := Open(ctx, source, options(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Transact(ctx, 0, actor(t), func(w ports.Writer) error { return w.CreateAccount(account(t)) }); err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if info, statErr := os.Stat(source + suffix); statErr != nil || info.Size() == 0 {
			t.Fatalf("fixture has no %s: %v", suffix, statErr)
		}
	}

	for _, retainSHM := range []bool{true, false} {
		t.Run(fmt.Sprintf("source-shm-%t", retainSHM), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "evidence", "state.db")
			if err := privateDirectory(filepath.Dir(target)); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"", "-wal", "-shm", witnessSuffix} {
				if suffix == "-shm" && !retainSHM {
					continue
				}
				data, readErr := os.ReadFile(source + suffix)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if writeErr := os.WriteFile(target+suffix, data, 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			before := retainedEvidenceHashes(t, target)
			inspection, inspectErr := InspectCommitWitness(ctx, target)
			if inspectErr != nil || inspection.Status != "verified" {
				t.Fatal("commit-witness inspection", inspection, inspectErr)
			}
			if after := retainedEvidenceHashes(t, target); !reflect.DeepEqual(before, after) {
				t.Fatalf("commit-witness inspection changed evidence\nbefore=%v\nafter=%v", before, after)
			}
			readOnly, inspectErr := Inspect(ctx, target, options(t))
			if inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if _, inspectErr = readOnly.State(ctx); inspectErr != nil {
				readOnly.Close()
				t.Fatal(inspectErr)
			}
			if inspectErr = readOnly.Close(); inspectErr != nil {
				t.Fatal(inspectErr)
			}
			if after := retainedEvidenceHashes(t, target); !reflect.DeepEqual(before, after) {
				t.Fatalf("Store inspection changed evidence\nbefore=%v\nafter=%v", before, after)
			}
		})
	}
}

func retainedEvidenceHashes(t *testing.T, path string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, suffix := range []string{"", "-wal", "-shm", ".lock", witnessSuffix, pendingSuffix} {
		data, err := os.ReadFile(path + suffix)
		if os.IsNotExist(err) {
			out[suffix] = "absent"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		out[suffix] = fmt.Sprintf("%x:%d", sha256.Sum256(data), len(data))
	}
	return out
}
