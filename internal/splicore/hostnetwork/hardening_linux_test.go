package hostnetwork

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPhase15JournalTemporarySymlinkAndPermissions(t *testing.T) {
	for _, kind := range []string{"symlink", "public"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "journal")
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			s.Close()
			outside := filepath.Join(t.TempDir(), "operator-owned")
			if err = os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			temp := filepath.Join(dir, ".journal-unsafe")
			if kind == "symlink" {
				err = os.Symlink(outside, temp)
			} else {
				err = os.WriteFile(temp, []byte("public"), 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if s, err = OpenStore(dir); err == nil {
				s.Close()
				t.Fatal("unsafe temporary accepted")
			}
			if b, err := os.ReadFile(outside); err != nil || string(b) != "preserve" {
				t.Fatal("external file modified", err)
			}
		})
	}
}
