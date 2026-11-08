package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func TestDaemonHTTPRestartReleasesListener(t *testing.T) {
	address := "127.0.0.1:0"
	// A new server is required after Shutdown; reuse the exact listening address.
	for range 2 {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal("restart could not bind released address:", err)
		}
		address = listener.Addr().String()
		ctx, cancel := context.WithCancel(context.Background())
		server := transport.Server(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		done := make(chan error, 1)
		go func() { done <- serveHTTP(ctx, server, listener, func() error { return nil }) }()
		joined := false
		t.Cleanup(func() {
			cancel()
			if !joined {
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("HTTP daemon did not exit")
				}
			}
			listener.Close()
		})
		client := &http.Client{Transport: &http.Transport{}, Timeout: 3 * time.Second}
		t.Cleanup(client.CloseIdleConnections)
		response, err := client.Get("http://" + address)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("unexpected response:", response.StatusCode)
		}
		duplicate, err := net.Listen("tcp4", address)
		if err == nil {
			duplicate.Close()
			t.Fatal("duplicate listener accepted")
		}
		cancel()
		select {
		case err := <-done:
			joined = true
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown did not join")
		}
	}
	probe, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatal("listener retained after final shutdown:", err)
	}
	probe.Close()
}

type failingAcceptListener struct {
	net.Listener
	err error
}

func (l failingAcceptListener) Accept() (net.Conn, error) { return nil, l.err }

func TestDaemonHTTPAcceptFailureReleasesListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fault := errors.New("permanent accept failure")
	ready := false
	err = serveHTTP(context.Background(), transport.Server(http.NotFoundHandler()), failingAcceptListener{listener, fault}, func() error {
		ready = true
		return nil
	})
	if !ready || !errors.Is(err, fault) {
		t.Fatal("accept failure discarded:", err)
	}
	probe, err := net.Listen("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal("failed listener retained:", err)
	}
	probe.Close()
}

func TestDaemonCanceledBeforeStartup(t *testing.T) {
	for _, name := range []string{"cancel", "deadline"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if name == "deadline" {
				ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
				defer cancel()
			}
			c := config.Config{Schema: 1, StateDirectory: t.TempDir(), API: config.API{UnixSocket: filepath.Join(t.TempDir(), "control.sock")}}
			if err := Serve(ctx, c); !errors.Is(err, ctx.Err()) {
				t.Fatal("startup lost cancellation:", err)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			err = serveHTTP(ctx, transport.Server(http.NotFoundHandler()), listener, func() error {
				t.Error("canceled daemon reported ready")
				return nil
			})
			if !errors.Is(err, ctx.Err()) {
				t.Fatal("HTTP startup lost cancellation:", err)
			}
		})
	}
}
