package operations

import (
	"context"
	"os"
	"path/filepath"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
)

// RecoverHost runs after the daemon has exited, under its original service user.
// It never enables SQLite intent and never fabricates records from OS state.
func RecoverHost(ctx context.Context, c config.Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	directory := filepath.Join(c.StateDirectory, "host-network")
	if _, err := os.Lstat(directory); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	store, err := hostnetwork.OpenStore(directory)
	if err != nil {
		return err
	}
	manager, err := hostnetwork.New(hostnetwork.NewPlatform(), store)
	if manager == nil {
		store.Close()
		return err
	}
	defer manager.Close()
	if err != nil {
		return err
	}
	return manager.Recover(ctx)
}
