package operations

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/version"
)

type phase15CanceledProjection struct {
	hostileSource
	cancel context.CancelFunc
}

func (s phase15CanceledProjection) System(ctx context.Context) (application.System, error) {
	s.cancel()
	return s.hostileSource.System(ctx)
}
func TestPhase15SupportCanceledDuringProjectionLeavesNoArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := filepath.Join(dir, "support.tar.gz")
	c := config.Config{Schema: 1, StateDirectory: dir, API: config.API{UnixSocket: filepath.Join(dir, "api.sock")}}
	err := SupportBundle(ctx, c, version.Current(), phase15CanceledProjection{hostileSource{"SYNTHETIC_SECRET"}, cancel}, output)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("projection cancellation lost", err)
	}
	if _, err = os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("canceled projection created output", err)
	}
}
