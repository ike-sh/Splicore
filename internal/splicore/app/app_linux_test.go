package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func TestFoundationDaemonLifecycle(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Schema: 1, StateDirectory: filepath.Join(dir, "state"), API: config.API{UnixSocket: filepath.Join(dir, "private", "control.sock")}}
	stop := startFoundationDaemon(t, c)
	stop()
}

func startFoundationDaemon(t *testing.T, c config.Config) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, c) }()
	joined := false
	stop := func() {
		t.Helper()
		cancel()
		if joined {
			return
		}
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("shutdown stuck")
		}
		if _, err := os.Stat(c.API.UnixSocket); !os.IsNotExist(err) {
			t.Error("owned socket not removed")
		}
	}
	t.Cleanup(stop)
	client := transport.UnixClient(c.API.UnixSocket)
	defer client.Close()
	deadline := time.Now().Add(5 * time.Second)
	ready, cancelReady := context.WithDeadline(ctx, deadline)
	defer cancelReady()
	for {
		system, err := client.System(ready)
		if err == nil {
			if system.DBSchema != version.DatabaseSchema || system.Health != "healthy" || system.ClientRuntime == nil || system.ClientRuntime.Health != "healthy" {
				t.Fatal("runtime maturity overstated")
			}
			break
		}
		select {
		case serveErr := <-done:
			joined = true
			t.Fatal("daemon exited before readiness:", serveErr, "client:", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon did not become ready", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return stop
}

func TestDaemonDuplicateStartAndRestart(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Schema: 1, StateDirectory: filepath.Join(dir, "state"), API: config.API{UnixSocket: filepath.Join(dir, "private", "control.sock")}}
	for range 2 {
		stop := startFoundationDaemon(t, c)
		err := Serve(context.Background(), c)
		var failure *identity.Error
		if !errors.As(err, &failure) || failure.Code != identity.Unavailable || failure.Message != "control socket already exists; operator review required" {
			t.Fatal("duplicate daemon did not reject owned socket:", err)
		}
		client := transport.UnixClient(c.API.UnixSocket)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.System(ctx)
		cancel()
		client.Close()
		if err != nil {
			t.Fatal("duplicate start affected active daemon:", err)
		}
		stop()
	}
}

func TestDaemonStartupFailureReleasesSocket(t *testing.T) {
	dir := t.TempDir()
	c := config.Config{Schema: 1, StateDirectory: filepath.Join(dir, "state"), KeyFile: filepath.Join(dir, "private", "missing.key"), API: config.API{UnixSocket: filepath.Join(dir, "private", "control.sock")}}
	err := Serve(context.Background(), c)
	var failure *identity.Error
	if !errors.As(err, &failure) || failure.Code != identity.Invalid || failure.Message != "key file must be a private regular 32-byte file" {
		t.Fatal("startup did not propagate key initialization failure:", err)
	}
	if _, err := os.Stat(c.API.UnixSocket); !os.IsNotExist(err) {
		t.Fatal("startup rollback retained socket:", err)
	}
	listener, err := transport.Listen(c.API.UnixSocket)
	if err != nil {
		t.Fatal("rollback did not allow immediate rebind:", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
