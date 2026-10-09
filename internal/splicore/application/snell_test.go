package application_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/api"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
	"github.com/ike-sh/Splicore/internal/splicore/storage/sqlite"
	"github.com/ike-sh/Splicore/internal/splicore/transport"
	"github.com/ike-sh/Splicore/internal/splicore/version"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func setupSnell(t *testing.T, path string, repoWrap func(ports.RuntimeRepository) ports.Repository) (*application.Service, *sqlite.Store) {
	t.Helper()
	p, e, x, err := testfixture.Phase2()
	if err != nil {
		t.Fatal(err)
	}
	vault, _ := secretvault.New("test", make([]byte, 32))
	store, err := sqlite.Open(context.Background(), path, sqlite.Options{Cipher: vault, ValidateInbound: func(i access.Inbound) error {
		p, e := p.Get(i.Protocol)
		if e != nil {
			return e
		}
		return p.ValidateInbound(i)
	}, CredentialKinds: func(k access.ProtocolKey) ([]access.CredentialKind, error) {
		p, e := p.Get(k)
		if e != nil {
			return nil, e
		}
		return p.Metadata().CredentialKinds, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	var repo ports.Repository = store
	if repoWrap != nil {
		repo = repoWrap(store)
	}
	s, err := application.New(repo, p, e, x, version.Current())
	if err == nil {
		err = s.EnableRuntime(context.Background())
	}
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return s, store
}
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := uint16(l.Addr().(*net.TCPAddr).Port)
	l.Close()
	return p
}
func doc(p uint16, v int) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"schema":1,"account_name":"synthetic-account","name":"synthetic-snell","listener":{"host":"127.0.0.1","port":%d},"display_endpoint":{"host":"127.0.0.1","port":%d},"settings":{"version":%d}}`, p, p, v))
}
func apply(t *testing.T, s *application.Service, d json.RawMessage) application.ApplyResult {
	t.Helper()
	p, e := s.PlanSnell(context.Background(), d)
	if e != nil {
		t.Fatal(e)
	}
	a, e := s.ApplySnell(context.Background(), application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func stop(t *testing.T, s *application.Service, store *sqlite.Store) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := s.CloseRuntime(ctx); e != nil {
		t.Fatal(e)
	}
	if e := s.CloseRuntime(ctx); e != nil {
		t.Fatal(e)
	}
	store.Close()
}
func assertReleased(t *testing.T, p uint16) {
	t.Helper()
	l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if e != nil {
		t.Fatal("listener leaked", e)
	}
	l.Close()
}
func TestSnellApplyAPIRecoveryDisplay(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupSnell(t, path, nil)
	defer func() { stop(t, s, store) }()
	p := freePort(t)
	server := httptest.NewServer(api.Handler(s))
	defer server.Close()
	client := transport.TestClient(server.Client(), server.URL)
	defer client.Close()
	d := doc(p, 6)
	planned, e := client.PlanSnell(ctx, d)
	if e != nil {
		t.Fatal(e)
	}
	a, e := client.ApplySnell(ctx, application.ApplyRequest{Document: d, Digest: planned.Digest, Revision: planned.Revision})
	if e != nil {
		t.Fatal(e)
	}
	export, e := client.ExportSnell(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1"})
	if e != nil {
		t.Fatal(e)
	}
	var secretConfig struct {
		PSK string `json:"psk"`
	}
	json.Unmarshal([]byte(export.Content), &secretConfig)
	page, e := client.Inbounds(ctx)
	if e != nil || len(page.Items) != 1 || page.Items[0].Health != "healthy" {
		t.Fatal("metadata")
	}
	raw, _ := json.Marshal(page)
	system, _ := s.System(ctx)
	sys, _ := json.Marshal(system)
	doctor, _ := s.Doctor(ctx, "test")
	diag, _ := json.Marshal(doctor)
	for _, b := range [][]byte{raw, sys, diag} {
		if strings.Contains(string(b), secretConfig.PSK) {
			t.Fatal("secret exposed")
		}
	}
	for _, host := range []string{"192.0.2.17", "2001:db8::17", "node.example.invalid"} {
		view, _ := s.Inbound(ctx, a.InboundID)
		state, _ := store.State(ctx)
		_, e = s.SetDisplay(ctx, a.InboundID, application.DisplayRequest{Endpoint: access.Endpoint{Host: host, Port: 30443}, ResourceRevision: view.Inbound.Revision, Revision: state.Revision})
		if e != nil {
			t.Fatal(e)
		}
		v, _ := s.Inbound(ctx, a.InboundID)
		if v.Inbound.Listeners[0].Endpoint.Port != p || v.Inbound.Listeners[0].Endpoint.Host != "127.0.0.1" {
			t.Fatal("display changed listener")
		}
		x, e := s.ExportSnell(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1"})
		if e != nil || !strings.Contains(x.Content, host) {
			t.Fatal("display projection")
		}
	}
	// Close unauthenticated connections and release listener, then restore solely from SQLite.
	c, e := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	stop(t, s, store)
	assertReleased(t, p)
	s, store = setupSnell(t, path, nil)
	v, e := s.Inbound(ctx, a.InboundID)
	if e != nil || v.Health != "healthy" || v.Inbound.Listeners[0].Endpoint.Port != p {
		t.Fatal("recovery failed")
	}
	restored, e := s.ExportSnell(ctx, a.InboundID, application.ExportRequest{Format: ports.SingBox, ClientVersion: "1.14.1"})
	if e != nil || !strings.Contains(restored.Content, secretConfig.PSK) {
		t.Fatal("credential recovery")
	}
}

type failCommit struct{ ports.RuntimeRepository }

func (f failCommit) CommitOperation(ctx context.Context, op identity.Transaction, fn func(ports.Writer) error) error {
	return f.RuntimeRepository.CommitOperation(ctx, op, func(w ports.Writer) error { return fn(failingWriter{w}) })
}

type failingWriter struct{ ports.Writer }

func (failingWriter) CreateCredential(access.Credential) error {
	return errors.New("SyntheticSecretShouldNeverEscape")
}
func TestSnellFailureRollback(t *testing.T) {
	for _, mode := range []string{"port", "storage"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state", "state.db")
			var wrap func(ports.RuntimeRepository) ports.Repository
			if mode == "storage" {
				wrap = func(r ports.RuntimeRepository) ports.Repository { return failCommit{r} }
			}
			s, store := setupSnell(t, path, wrap)
			defer stop(t, s, store)
			p := freePort(t)
			if mode == "port" {
				l, e := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
			}
			d := doc(p, 5)
			planned, e := s.PlanSnell(context.Background(), d)
			if e != nil {
				t.Fatal(e)
			}
			_, e = s.ApplySnell(context.Background(), application.ApplyRequest{Document: d, Digest: planned.Digest, Revision: planned.Revision})
			if e == nil {
				t.Fatal("failure accepted")
			}
			if mode == "port" {
				var de *identity.Error
				if !errors.As(e, &de) || de.Code != identity.PortConflict {
					t.Fatal("port conflict not typed", e)
				}
			}
			if strings.Contains(e.Error(), "SyntheticSecretShouldNeverEscape") {
				t.Fatal("storage error leaked")
			}
			state, _ := store.State(context.Background())
			page, _ := s.Inbounds(context.Background())
			if state.Revision != 0 || state.PendingTransactions != 0 || len(page.Items) != 0 {
				t.Fatal("half commit")
			}
			if mode == "storage" {
				assertReleased(t, p)
			}
		})
	}
}
func TestSnellConcurrentRevisionAndInterruptedCreate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "state.db")
	s, store := setupSnell(t, path, nil)
	defer func() { stop(t, s, store) }()
	plans := []application.ApplyRequest{}
	for range 6 {
		d := doc(freePort(t), 5)
		p, e := s.PlanSnell(ctx, d)
		if e != nil {
			t.Fatal(e)
		}
		plans = append(plans, application.ApplyRequest{Document: d, Digest: p.Digest, Revision: p.Revision})
	}
	var wg sync.WaitGroup
	success := 0
	var mu sync.Mutex
	for _, p := range plans {
		wg.Go(func() {
			_, e := s.ApplySnell(ctx, p)
			if e == nil {
				mu.Lock()
				success++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if success != 1 {
		t.Fatal("competing revisions committed")
	}
	id, _ := identity.NewID()
	if _, e := store.BeginOperation(ctx, 1, identity.Actor{Principal: "synthetic", RequestID: id}); e != nil {
		t.Fatal(e)
	}
	stop(t, s, store)
	s, store = setupSnell(t, path, nil)
	state, _ := store.State(ctx)
	page, _ := s.Inbounds(ctx)
	if state.Revision != 1 || state.PendingTransactions != 0 || len(page.Items) != 1 {
		t.Fatal("pending recovery")
	}
}
func TestSnellInvalidAndPlanBinding(t *testing.T) {
	s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
	defer stop(t, s, store)
	d := doc(freePort(t), 5)
	for _, value := range []string{`""`, `null`, `"short"`, `123`, `[]`} {
		input := append(append([]byte{}, d[:len(d)-1]...), []byte(`,"psk":`+value+`}`)...)
		if _, e := application.DecodeSnell(input); e == nil {
			t.Fatal("explicit invalid PSK accepted")
		}
	}
	supplied := append(append([]byte{}, d[:len(d)-1]...), []byte(`,"psk":"SyntheticExplicitPSKPhase20001"}`)...)
	decoded, decodeErr := application.DecodeSnell(supplied)
	if decodeErr != nil || decoded.PSK.Reveal() != "SyntheticExplicitPSKPhase20001" {
		t.Fatal("supplied PSK changed")
	}
	p, e := s.PlanSnell(context.Background(), d)
	if e != nil {
		t.Fatal(e)
	}
	bad := strings.Replace(string(d), `"version":5`, `"version":4`, 1)
	if s.ValidateSnell(context.Background(), []byte(bad)) == nil {
		t.Fatal("invalid version")
	}
	changed := strings.Replace(string(d), "synthetic-account", "changed-account", 1)
	if _, e = s.ApplySnell(context.Background(), application.ApplyRequest{Document: []byte(changed), Digest: p.Digest, Revision: p.Revision}); e == nil {
		t.Fatal("changed plan accepted")
	}
	state, _ := store.State(context.Background())
	if state.Revision != 0 || state.PendingTransactions != 0 {
		t.Fatal("invalid candidate persisted")
	}
}
