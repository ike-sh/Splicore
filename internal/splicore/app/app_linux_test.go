package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/transport"
)

func TestFoundationDaemonLifecycle(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Schema: 1, StateDirectory: filepath.Join(dir, "state"), API: config.API{UnixSocket: filepath.Join(dir, "private", "control.sock")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c) }()
	client := transport.UnixClient(c.API.UnixSocket)
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		system, err := client.System(context.Background())
		if err == nil {
			if system.DBSchema != 2 || system.Health != "healthy" {
				t.Fatal("runtime maturity overstated")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not become ready", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown stuck")
	}
	if _, err := os.Stat(c.API.UnixSocket); !os.IsNotExist(err) {
		t.Fatal("owned socket not removed")
	}
}
