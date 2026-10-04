// Package app is the composition root; dependencies meet only here.
package app

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/config"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/operations"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/secretvault"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/transport"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

func Serve(ctx context.Context, c config.Config) error {
	if err := c.Validate(); err != nil {
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
	defer store.Close()
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
		_ = service.CloseRuntime(shutdown)
	}()
	outbounds, err := registry.NewOutbounds(native.SnellOutboundFactory{}, native.Hysteria2OutboundFactory{}, native.TUICOutboundFactory{}, native.VLESSOutboundFactory{}, native.MieruOutboundFactory{})
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
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdown)
		case <-done:
		}
	}()
	if err = operations.NotifyReady(); err != nil {
		close(done)
		return err
	}
	err = server.Serve(listener)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
