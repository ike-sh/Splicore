package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

// Check validates bootstrap resources and any existing committed configuration.
// A fresh installation may have no database yet. No listener/worker is started.
func Check(ctx context.Context, c config.Config) (err error) {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := transport.CheckControlPath(c.API.UnixSocket); err != nil {
		return err
	}
	var cipher ports.Cipher
	if c.KeyFile != "" {
		cipher, err = secretvault.LoadFile(c.KeyFile)
		if err != nil {
			return err
		}
	}
	p, engines, exporters, err := registry.NativeCore()
	if err != nil {
		return err
	}
	path := filepath.Join(c.StateDirectory, "state.db")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return identity.Err(identity.Unavailable, "invalid or corrupt committed state")
	}
	store, err := sqlite.Inspect(ctx, path, sqlite.Options{Cipher: cipher})
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := application.New(store, p, engines, exporters, version.Current())
	if err != nil {
		return err
	}
	return service.CheckCommitted(ctx)
}
