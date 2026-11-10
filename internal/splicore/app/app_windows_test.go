package app

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func TestDaemonProductionTransportBoundary(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Schema: 1, StateDirectory: filepath.Join(dir, "state"), KeyFile: filepath.Join(dir, "keys", "master.key"), API: config.API{UnixSocket: filepath.Join(dir, "control.sock")}}
	if !transport.ProductionSupported() {
		t.Fatal("Windows production transport unavailable")
	}
	if err := secretvault.InitFile(c.KeyFile); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, c) }()
		client := transport.UnixClient(c.API.UnixSocket)
		deadline := time.Now().Add(5 * time.Second)
		for {
			_, err := client.System(ctx)
			if err == nil {
				break
			}
			select {
			case err := <-done:
				cancel()
				t.Fatal("daemon startup failed:", err)
			default:
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("daemon did not become ready:", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		duplicate := Serve(context.Background(), c)
		var failure *identity.Error
		if !errors.As(duplicate, &failure) || failure.Code != identity.Unavailable {
			cancel()
			t.Fatal("duplicate daemon admitted:", duplicate)
		}
		if err := Check(ctx, c); err != nil {
			cancel()
			t.Fatal("offline committed check:", err)
		}
		client.Close()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown stuck")
		}
		listener, err := transport.Listen(c.API.UnixSocket)
		if err != nil {
			t.Fatal("pipe not released:", err)
		}
		listener.Close()
	}
}
