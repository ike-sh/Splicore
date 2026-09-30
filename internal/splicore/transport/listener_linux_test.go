package transport

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketPermissionsAndPeer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "control.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o660 {
		t.Fatal("socket permissions")
	}
	server := Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := Peer(r.Context())
		if !ok || peer.UID != uint32(os.Geteuid()) || peer.PID <= 0 {
			t.Error("peer not authenticated")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	go server.Serve(listener)
	client := UnixClient(path)
	defer client.Close()
	if _, err = client.System(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = Listen(path); err == nil {
		t.Fatal("existing socket overwritten")
	}
	unsafe := t.TempDir()
	if err = os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err = Listen(filepath.Join(unsafe, "unsafe.sock")); err == nil {
		t.Fatal("unsafe directory admitted")
	}
}
