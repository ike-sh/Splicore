package application_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
)

func TestPhase15LateProviderFailureCannotDegradeReplacement(t *testing.T) {
	for _, kind := range []string{"proxy", "ruleset"} {
		for _, failure := range []string{"fetch", "parse"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
				defer stop(t, s, store)
				enableClient(t, s)
				entered := make(chan struct{})
				release := make(chan struct{})
				fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if failure == "fetch" {
						w.WriteHeader(503)
					} else {
						_, _ = w.Write([]byte("{synthetic-malformed"))
					}
				}))
				defer func() { cancel(); close(release); fixture.Close() }()
				format := "canonical"
				if kind == "ruleset" {
					format = "canonical-rules"
				}
				plan := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "old", Kind: kind, Format: format, AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL}})
				done := make(chan error, 1)
				go func() { _, err := s.RefreshProvider(ctx, plan.ProviderID); done <- err }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("fetch did not start")
				}
				state, err := s.ClientStatus(ctx)
				if err != nil {
					t.Fatal(err)
				}
				prior := state.State.Management.Providers[0]
				replacement := provider.Provider{ID: prior.ID, RuleSetID: prior.RuleSetID, Name: "replacement", Kind: kind, Format: format, AllowPrivate: true}
				managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", ID: prior.ID, Provider: &replacement, Source: &provider.Source{URL: fixture.URL + "/replacement"}})
				before, err := s.ClientStatus(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// Closing the channel is owned by cleanup; one send releases exactly this request.
				release <- struct{}{}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("old faulty response admitted")
					}
				case <-ctx.Done():
					t.Fatal("refresh did not finish")
				}
				after, err := s.ClientStatus(ctx)
				if err != nil {
					t.Fatal(err)
				}
				p := after.State.Management.Providers[0]
				if after.State.Revision != before.State.Revision || p.LastError != "" || p.Failures != 0 || p.Status == "degraded" {
					t.Fatal("old completion mutated replacement authority")
				}
			})
		}
	}
}

func TestPhase15LateProviderSuccessCannotReplaceNewAuthority(t *testing.T) {
	for _, kind := range []string{"proxy", "ruleset"} {
		for _, mutation := range []string{"update", "delete", "restart", "shutdown"} {
			t.Run(kind+"/"+mutation, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				s, store := setupSnell(t, filepath.Join(t.TempDir(), "state", "state.db"), nil)
				defer stop(t, s, store)
				enableClient(t, s)
				entered := make(chan struct{})
				release := make(chan struct{})
				body := `{"schema_version":1,"rules":[{"domain_suffixes":["owned.test"]}]}`
				format := "canonical-rules"
				if kind == "proxy" {
					psk, err := snell.GeneratePSK()
					if err != nil {
						t.Fatal(err)
					}
					body = feedDocument([]nodeimport.Candidate{snellCandidate("owned", access.Endpoint{Host: "127.0.0.1", Port: 1}, psk.Reveal())})
					format = "canonical"
				}
				fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					_, _ = w.Write([]byte(body))
				}))
				defer func() { cancel(); close(release); fixture.Close() }()
				plan := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "old", Kind: kind, Format: format, AllowPrivate: true}, Source: &provider.Source{URL: fixture.URL}})
				done := make(chan error, 1)
				go func() { _, err := s.RefreshProvider(ctx, plan.ProviderID); done <- err }()
				select {
				case <-entered:
				case <-ctx.Done():
					t.Fatal("fetch did not reach barrier")
				}
				switch mutation {
				case "update":
					current, err := store.ClientState(ctx)
					if err != nil {
						t.Fatal(err)
					}
					updated := provider.Provider{ID: plan.ProviderID, RuleSetID: current.Management.Providers[0].RuleSetID, Name: "new", Kind: kind, Format: format, AllowPrivate: true}
					managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", ID: plan.ProviderID, Provider: &updated, Source: &provider.Source{URL: fixture.URL + "/new"}})
				case "delete":
					managementApply(t, s, application.ManagementRequest{Operation: "provider-delete", ID: plan.ProviderID})
				case "restart":
					clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "restart"})
				case "shutdown":
					if err := s.CloseRuntime(ctx); err != nil {
						t.Fatal(err)
					}
				}
				before, err := store.ClientState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// Release is closed by cleanup; a buffered completion avoids a shutdown send.
				if mutation != "shutdown" {
					release <- struct{}{}
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("stale completion accepted")
					}
				case <-ctx.Done():
					t.Fatal("refresh/shutdown failed to join")
				}
				after, err := store.ClientState(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if after.Revision != before.Revision || len(after.Nodes) != len(before.Nodes) || len(after.Network.RuleSets) != len(before.Network.RuleSets) {
					t.Fatal("late response replaced newer authority")
				}
				diagnostics, err := s.ProviderDiagnostics(ctx)
				if err != nil || diagnostics.ActiveRefreshes != 0 {
					t.Fatal("refresh worker not released", err)
				}
			})
		}
	}
}
