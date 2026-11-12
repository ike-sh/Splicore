package sqlite

// This is a reconciliation experiment, not a production file format or commit
// protocol. It deliberately demonstrates the common-rollback counterexample.
import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type designAnchor struct {
	Version  int
	Epoch    string
	Node     identity.ID
	KeyID    string
	Revision identity.Revision
	Digest   string
	Phase    string
}

type designEnvelope struct {
	Record designAnchor
	MAC    string
}

func designDigest(t *testing.T, s *Store) string {
	t.Helper()
	b, err := json.Marshal(admissionLogicalSnapshot(t, s).Tables)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func designEncode(t *testing.T, a designAnchor, key []byte) []byte {
	t.Helper()
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("splicore-anchor-design-only-v1\x00"))
	m.Write(b)
	out, err := json.Marshal(designEnvelope{a, hex.EncodeToString(m.Sum(nil))})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Only exact, authenticated confirmed state is eligible in this experiment.
// Unknown state is never repaired by rewriting the oracle from the database.
func designReconcile(data, key []byte, expected designAnchor) error {
	var e designEnvelope
	if len(key) != 32 || json.Unmarshal(data, &e) != nil {
		return errors.New("missing or invalid acknowledgement/key")
	}
	b, err := json.Marshal(e.Record)
	if err != nil {
		return err
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte("splicore-anchor-design-only-v1\x00"))
	m.Write(b)
	mac, err := hex.DecodeString(e.MAC)
	if err != nil || !hmac.Equal(mac, m.Sum(nil)) {
		return errors.New("acknowledgement authentication failed")
	}
	if e.Record != expected || e.Record.Phase != "confirmed" || e.Record.Version != 1 {
		return errors.New("recovery review required")
	}
	return nil
}

func TestIndependentAcknowledgementDesign(t *testing.T) {
	s, path := newStore(t)
	ctx := context.Background()
	p3account(t, s, 0, "confirmed-baseline")
	state, err := s.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := designAnchor{1, string(newID(t)), state.NodeID, "fixture-key", state.Revision, designDigest(t, s), "confirmed"}
	key := make([]byte, 32)
	key[0] = 7 // Synthetic fixture key only; never exported in evidence.
	baseBytes := designEncode(t, base, key)
	anchorRoot := t.TempDir() // Separate file, but still the same physical medium.
	anchorPath := filepath.Join(anchorRoot, "design-confirmed.json")
	f, err := os.OpenFile(anchorPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write(baseBytes); err != nil {
		t.Fatal(err)
	}
	if err = f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" {
		d, err := os.Open(anchorRoot)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Sync(); err != nil {
			t.Fatal(err)
		}
		d.Close()
	}
	// Actual SQLite FULL commit occurs before external confirmation in this cut.
	p3account(t, s, 1, "db-committed-external-confirmation-not-persisted")
	next := base
	next.Revision, next.Digest = 2, designDigest(t, s)
	nextBytes := designEncode(t, next, key)
	prepared := next
	prepared.Phase = "prepared"
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 1
	wrongNode, wrongEpoch, wrongDigest := next, next, next
	wrongNode.Node, wrongEpoch.Epoch, wrongDigest.Digest = newID(t), string(newID(t)), base.Digest
	corrupt := append([]byte(nil), nextBytes...)
	corrupt[len(corrupt)-3] ^= 1
	cases := []struct {
		name string
		data []byte
		key  []byte
		db   designAnchor
		ok   bool
	}{
		{"normal-confirmed-commit", nextBytes, key, next, true},
		{"crash-before-db-commit-with-prepared-intent", designEncode(t, prepared, key), key, base, false},
		{"db-committed-confirmation-missing", baseBytes, key, next, false},
		{"db-committed-prepared-record-only", designEncode(t, prepared, key), key, next, false},
		{"external-confirmed-db-content-lost", nextBytes, key, base, false},
		{"missing-anchor-no-bootstrap", nil, key, next, false},
		{"legacy-db-no-anchor-no-auto-upgrade", nil, key, base, false},
		{"corrupt-anchor", corrupt, key, next, false},
		{"vault-key-missing", nextBytes, nil, next, false},
		{"vault-key-mismatch", nextBytes, wrongKey, next, false},
		{"other-installation", nextBytes, key, wrongNode, false},
		{"other-restore-epoch", nextBytes, key, wrongEpoch, false},
		{"same-revision-different-content", nextBytes, key, wrongDigest, false},
		{"old-backup-with-current-anchor", nextBytes, key, base, false},
		{"verified-matching-backup-pair-in-explicit-test-epoch", baseBytes, key, base, true},
		// Authentication is not freshness. A coordinated rollback of both valid
		// files to the same old generation cannot be detected by this design.
		{"COUNTEREXAMPLE-same-medium-coordinated-rollback", baseBytes, key, base, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := admissionFiles(t, path)
			if err := designReconcile(tc.data, tc.key, tc.db); (err == nil) != tc.ok {
				t.Fatal("unexpected reconciliation", err)
			}
			after := admissionFiles(t, path)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("design reconciliation modified SQLite files")
			}
			stored, err := os.ReadFile(anchorPath)
			if err != nil || !reflect.DeepEqual(stored, baseBytes) {
				t.Fatal("reconciliation rewrote the independent oracle", err)
			}
			admissionEvidence(t, "design-only", map[string][]byte{"anchor-input.json": tc.data, "unchanged-anchor.json": stored}, map[string]any{"accepted": tc.ok, "database_generation": tc.db, "production_integration": "NOT_QUALIFIED", "power_loss_and_atomic_replacement": "NOT_EXECUTED"})
		})
	}
}
