package sqlite

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestInspectIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "state.db")
	s, err := Open(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Inspect(context.Background(), path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Exec("CREATE TABLE forbidden_write(id INTEGER)"); err == nil {
		t.Fatal("inspection allowed writes")
	}
	if _, err := r.State(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("inspection changed database bytes", err)
	}
}

func TestInspectDoesNotInitialize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "absent")
	if s, err := Inspect(context.Background(), filepath.Join(dir, "state.db"), Options{}); err == nil {
		s.Close()
		t.Fatal("inspection initialized absent state")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("inspection created a directory")
	}
}
