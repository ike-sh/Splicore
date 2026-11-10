package app

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/config"
)

func TestBootstrapFailsBeforeServing(t *testing.T) {
	c := config.Config{Schema: 2, StateDirectory: t.TempDir(), API: config.API{UnixSocket: filepath.Join(t.TempDir(), "control.sock")}}
	if Serve(context.Background(), c) == nil {
		t.Fatal("unsupported config served")
	}
}
