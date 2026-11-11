package hostnetwork

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPhase15JournalCrashTemporaryFileCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journal")
	first, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(dir, ".journal-crash-fixture")
	if err = os.WriteFile(temporary, []byte("partial derived snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, "operator-note")
	if err = os.WriteFile(unrelated, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	next, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err = os.Lstat(temporary); !os.IsNotExist(err) {
		t.Error("abandoned journal temporary retained", err)
	}
	if data, err := os.ReadFile(unrelated); err != nil || string(data) != "preserve" {
		t.Error("unrelated file changed", err)
	}
}
