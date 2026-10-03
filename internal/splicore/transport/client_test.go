package transport

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
