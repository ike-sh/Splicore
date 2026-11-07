package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/config"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
)

func TestWALRecoveryStartupErrorPropagation(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	path := filepath.Join(private, "state.db")
	s, e := sqlite.Open(context.Background(), path, sqlite.Options{})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	broken := bytes.Repeat([]byte{0xff}, 32)
	if e = os.WriteFile(path+"-wal", broken, 0600); e != nil {
		t.Fatal(e)
	}
	c := config.Config{Schema: 1, StateDirectory: private, API: config.API{UnixSocket: filepath.Join(root, "control.sock")}}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	bootstrap := filepath.Join(root, "bootstrap.json")
	if e = os.WriteFile(bootstrap, b, 0600); e != nil {
		t.Fatal(e)
	}
	var stdout, stderr bytes.Buffer
	initialized := false
	var openingError error
	status := Run(context.Background(), []string{"run", "--config", bootstrap}, &stdout, &stderr, Dependencies{Serve: func(ctx context.Context, c config.Config) error {
		store, err := sqlite.Open(ctx, filepath.Join(c.StateDirectory, "state.db"), sqlite.Options{})
		openingError = err
		if err != nil {
			return err
		}
		defer store.Close()
		initialized = true
		return nil
	}})
	var domain *identity.Error
	if status != 1 || initialized || !errors.As(openingError, &domain) || domain.Code != identity.Corrupt || !strings.Contains(domain.Message, "WAL corruption") || stderr.String() != string(identity.Corrupt)+": command rejected\n" || stdout.Len() != 0 {
		t.Fatal("startup corruption concealed", status, initialized, openingError, stdout.String(), stderr.String())
	}
	after, e := os.ReadFile(path + "-wal")
	if e != nil || !bytes.Equal(after, broken) {
		t.Fatal("startup modified corruption evidence", e)
	}
	t.Logf("startup initialized=%v exit=%d error=%v stderr=%q", initialized, status, openingError, stderr.String())
}
