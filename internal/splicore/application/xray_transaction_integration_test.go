//go:build splicore_xray_integration

package application_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/engine/xray"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

type xrayCommitProbe struct {
	ports.MultiBindingRepository
	address string
	t       *testing.T
	fail    bool
}

func (r xrayCommitProbe) CommitOperation(ctx context.Context, op identity.Transaction, write func(ports.Writer) error) error {
	c, err := net.DialTimeout("tcp", r.address, time.Second)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		r.t.Fatal("precommit admission", err)
	}
	if r.fail {
		return r.MultiBindingRepository.CommitOperation(ctx, op, func(w ports.Writer) error { return write(failingWriter{w}) })
	}
	return r.MultiBindingRepository.CommitOperation(ctx, op, write)
}
func TestXrayPinnedAdmissionCommitCompensationAndRequiredMissing(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			runtimeRoot := filepath.Join(root, "runtime")
			e := pinnedEngine(t, runtimeRoot)
			port := freePort(t)
			wrap := func(repo ports.MultiBindingRepository) ports.Repository {
				return xrayCommitProbe{repo, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), t, fail}
			}
			s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), wrap, composeXray(e))
			defer stop(t, s, store)
			d := xrayDocument(t, vlessDoc(t, port, v.Settings{Security: v.Plain, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp"}, ""))
			plan, err := s.PlanCreation(ctx, "vless", d)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ApplyCreation(ctx, "vless", application.ApplyRequest{Document: d, Digest: plan.Digest, Revision: plan.Revision})
			state, _ := store.State(ctx)
			inbounds, _ := store.Inbounds(ctx)
			if fail {
				if err == nil || state.Revision != 0 || state.PendingTransactions != 0 || len(inbounds) != 0 {
					t.Fatal("commit compensation")
				}
				entries, _ := os.ReadDir(runtimeRoot)
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), "generation-") {
						t.Fatal("rollback retained child artifact")
					}
				}
				l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
				if err != nil {
					t.Fatal("rollback retained listener")
				}
				_ = l.Close()
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.CloseRuntime(ctx) != nil {
				t.Fatal("close")
			}
			missing := xray.New(xray.Options{RuntimeDirectory: runtimeRoot})
			defer missing.Close(ctx)
			p, eng, exports, _ := composeXray(missing)()
			failed, err := application.New(store, p, eng, exports, version.Current())
			if err != nil {
				t.Fatal(err)
			}
			if err = failed.EnableRuntime(ctx); err == nil || !strings.Contains(err.Error(), "unavailable") {
				t.Fatal("required engine silently recovered", err)
			}
			system, err := failed.System(ctx)
			if err != nil || system.Health != "degraded" {
				t.Fatal("required unavailable status", err)
			}
			after, _ := store.Inbounds(ctx)
			afterState, _ := store.State(ctx)
			if after[0].Engine != "xray" || afterState.Revision != state.Revision {
				t.Fatal("missing engine changed committed placement")
			}
		})
	}
}
