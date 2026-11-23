package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestAbsentAndInvalidResponses(t *testing.T) {
	c := UnixClient(filepath.Join(t.TempDir(), "missing.sock"))
	defer c.Close()
	if _, err := c.System(context.Background()); !errors.Is(err, ErrNotRunning) {
		t.Fatal("absent daemon classification", err)
	}
	for _, body := range []string{"dummy-secret", strings.Repeat("x", 4<<20+1)} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}))
		client := TestClient(server.Client(), server.URL)
		if _, err := client.System(context.Background()); err == nil || strings.Contains(err.Error(), "dummy-secret") {
			t.Fatal("invalid response leaked or accepted")
		}
		client.Close()
		server.Close()
	}
}

func TestIntegrityFailureIdentitySurvivesControlTransport(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"storage_integrity_unverified","message":"storage integrity unverified","request_id":"fixture"}`))
	}))
	defer server.Close()
	client := TestClient(server.Client(), server.URL)
	defer client.Close()
	var out any
	err := client.post(context.Background(), "/mutation", []byte(`{}`), &out)
	var typed *identity.Error
	if !errors.As(err, &typed) || typed.Code != identity.StorageIntegrityUnverified {
		t.Fatal("control client discarded storage-integrity identity", err)
	}
}
