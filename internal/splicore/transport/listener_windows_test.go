package transport

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/privatefs"
)

func TestControlRejectsBroadPipeServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	name, err := controlPipe(path)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := privatefs.UserSID()
	if err != nil {
		t.Fatal(err)
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "O:" + sid.String() + "D:P(A;;GA;;;WD)"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		close(release)
		l.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture worker did not finish")
		}
	}()
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err == nil {
			<-release
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := dialControl(ctx, path); err == nil {
		c.Close()
		t.Fatal("trusted broad server ACL")
	} else {
		var rejected *identity.Error
		if !errors.As(err, &rejected) || rejected.Code != identity.Invalid {
			t.Fatal("rejected for a reason other than unsafe server identity/DACL:", err)
		}
	}
}
