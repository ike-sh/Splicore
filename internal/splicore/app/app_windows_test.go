package app

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
)

func TestDaemonProductionTransportBoundary(t *testing.T) {
	c := config.Config{Schema: 1, StateDirectory: t.TempDir(), API: config.API{UnixSocket: filepath.Join(t.TempDir(), "control.sock")}}
	err := Serve(context.Background(), c)
	var failure *identity.Error
	if transport.ProductionSupported() || !errors.As(err, &failure) || failure.Code != identity.NotImplemented {
		t.Fatal("unsupported production transport did not fail explicitly:", err)
	}
}
