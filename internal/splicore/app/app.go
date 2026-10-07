// Package app is the composition root; dependencies meet only here.
package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/operations"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

func Serve(ctx context.Context, c config.Config) (err error) {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listener, err := transport.Listen(c.API.UnixSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	p, e, x, err := registry.NativeCore()
	if err != nil {
		return err
	}
	var cipher ports.Cipher
	if c.KeyFile != "" {
		cipher, err = secretvault.LoadFile(c.KeyFile)
		if err != nil {
			return err
		}
	}
	store, err := sqlite.Open(ctx, filepath.Join(c.StateDirectory, "state.db"), sqlite.Options{Cipher: cipher, ValidateInbound: func(i access.Inbound) error {
		p, err := p.Get(i.Protocol)
		if err != nil {
			return err
		}
		return p.ValidateInbound(i)
	}, CredentialKinds: func(key access.ProtocolKey) ([]access.CredentialKind, error) {
		entry, err := p.Get(key)
		if err != nil {
			return nil, err
		}
		return entry.Metadata().CredentialKinds, nil
	}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	service, err := application.New(store, p, e, x, version.Current())
	if err != nil {
		return err
	}
	if err = service.EnableRuntime(ctx); err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = errors.Join(err, service.CloseRuntime(shutdown))
	}()
	outbounds, err := registry.NewOutbounds(native.SnellOutboundFactory{}, native.Hysteria2OutboundFactory{}, native.TUICOutboundFactory{}, native.VLESSOutboundFactory{}, native.MieruOutboundFactory{}, native.ShadowsocksOutboundFactory{}, native.TrojanOutboundFactory{}, native.VMessOutboundFactory{})
	if err != nil {
		return err
	}
	if err = service.EnableClientRuntime(ctx, outbounds, filepath.Join(c.StateDirectory, "host-network")); err != nil {
		return err
	}
	if err = service.StartManagement(ctx); err != nil {
		return err
	}
	server := transport.Server(api.Handler(service))
	return serveHTTP(ctx, server, listener, operations.NotifyReady)
}

// HTTP work must finish before application and SQLite ownership is released.
func serveHTTP(ctx context.Context, server *http.Server, listener net.Listener, ready func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	requests, cancelRequests := context.WithCancel(ctx)
	defer cancelRequests()
	server.BaseContext = func(net.Listener) context.Context { return requests }
	// Close terminates connections but does not join handlers. Seal admission
	// before waiting so even a handler scheduled after Close cannot use the app.
	var admission sync.Mutex
	var handlers sync.WaitGroup
	sealed := false
	handler := server.Handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.Lock()
		if sealed {
			admission.Unlock()
			return
		}
		handlers.Add(1)
		admission.Unlock()
		defer handlers.Done()
		handler.ServeHTTP(w, r)
	})
	defer func() {
		cancelRequests()
		admission.Lock()
		sealed = true
		admission.Unlock()
		handlers.Wait()
	}()
	done := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := server.Shutdown(shutdown)
			if err != nil {
				_ = server.Close()
			}
			finished <- err
		case <-done:
			finished <- nil
		}
	}()
	if err := ready(); err != nil {
		cancelRequests()
		close(done)
		_ = server.Close()
		return errors.Join(err, <-finished)
	}
	err := server.Serve(listener)
	if !errors.Is(err, http.ErrServerClosed) {
		cancelRequests()
	}
	close(done)
	shutdownErr := <-finished
	_ = server.Close()
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return errors.Join(err, shutdownErr)
}
