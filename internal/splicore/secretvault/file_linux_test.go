package secretvault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateKeyProvisioning(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "key")
	if e := InitFile(path); e != nil {
		t.Fatal(e)
	}
	if e := InitFile(path); e == nil {
		t.Fatal("existing key overwritten")
	}
	a, e := LoadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := LoadFile(path)
	if e != nil || a.KeyID() != b.KeyID() {
		t.Fatal("key identity changed")
	}
	cipher, _ := a.Seal([]byte("synthetic-plaintext"), []byte("owner"))
	plain, e := b.Open(cipher, []byte("owner"))
	if e != nil || !bytes.Equal(plain, []byte("synthetic-plaintext")) {
		t.Fatal("key reload failed")
	}
	os.Chmod(path, 0644)
	if _, e = LoadFile(path); e == nil {
		t.Fatal("public key file accepted")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if _, e = LoadFile(link); e == nil {
		t.Fatal("symlink key accepted")
	}
	os.WriteFile(path, []byte("short"), 0600)
	if _, e = LoadFile(path); e == nil {
		t.Fatal("invalid key accepted")
	}
}
