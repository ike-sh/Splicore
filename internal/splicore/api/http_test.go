package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/internal/splicore/api"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"github.com/sagernet/sing-box/internal/splicore/storage/sqlite"
	"github.com/sagernet/sing-box/internal/splicore/version"
)

func handler(t *testing.T) http.Handler {
	t.Helper()
	store, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "private", "state.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	p, e, x, _ := registry.Foundation()
	s, err := application.New(store, p, e, x, version.Current())
	if err != nil {
		t.Fatal(err)
	}
	return api.Handler(s)
}

func TestReadsValidationAndScope(t *testing.T) {
	h := handler(t)
	for _, path := range []string{"/api/v1/system", "/api/v1/capabilities?limit=1"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 200 || w.Header().Get("ETag") != `"0"` || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("read failed", w.Code)
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatal("response not JSON")
		}
		if strings.Contains(w.Body.String(), "password") || strings.Contains(w.Body.String(), "ciphertext") {
			t.Fatal("private payload in response")
		}
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"POST", "/api/v1/system", 405}, {"GET", "/api/v1/accounts", 404}, {"GET", "/api/v1/capabilities?limit=0", 400}, {"GET", "/api/v1/capabilities?limit=201", 400}, {"GET", "/api/v1/capabilities?limit=1&limit=2", 400}, {"GET", "/api/v1/capabilities?cursor=dummy-secret", 400}, {"GET", "/api/v1/system?token=dummy-secret", 400}, {"GET", "/api/v1/capabilities?unknown=x", 400}, {"GET", "/api/v1/capabilities?limit=%zz", 400}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Errorf("%s %s: %d", tc.method, tc.path, w.Code)
		}
		if strings.Contains(w.Body.String(), "dummy-secret") {
			t.Fatal("request echoed into problem")
		}
		var problem api.Problem
		if json.Unmarshal(w.Body.Bytes(), &problem) != nil || problem.RequestID == "" {
			t.Fatal("problem contract missing")
		}
	}
}

type unavailable struct{}

func (unavailable) System(context.Context) (application.System, error) {
	return application.System{}, identity.Err(identity.Unavailable, "dummy-password")
}

func (unavailable) Capabilities(context.Context, string, int) (application.CapabilityPage, error) {
	return application.CapabilityPage{}, identity.RevisionConflict(3)
}

func TestErrorMappingRedacts(t *testing.T) {
	for path, status := range map[string]int{"/api/v1/system": 503, "/api/v1/capabilities": 409} {
		w := httptest.NewRecorder()
		api.Handler(unavailable{}).ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != status || strings.Contains(w.Body.String(), "dummy-password") {
			t.Fatal("unsafe error mapping")
		}
	}
}
