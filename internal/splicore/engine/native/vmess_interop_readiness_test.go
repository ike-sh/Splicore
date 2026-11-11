package native

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestVMessMihomoReadinessWaitsForConfigurationCompletion(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rules":
			_, _ = w.Write([]byte(`{"rules":[{"Type":"Match","Proxy":"vmess-peer"}]}`))
		case "/configs":
			if r.Method != http.MethodPut || r.URL.Query().Get("force") != "true" || r.Header.Get("Content-Type") != "application/json" {
				t.Error("incorrect configuration completion request")
			}
			var body struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path != "synthetic-local-config.json" {
				t.Error("configuration path was not preserved")
			}
			puts.Add(1)
			close(entered)
			<-release
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("unexpected readiness operation")
		}
	}))
	defer func() {
		releaseOnce.Do(func() { close(release) })
		server.Close()
	}()
	client := server.Client()
	client.Timeout = 2 * time.Second
	done := make(chan error, 1)
	go func() { done <- vmessMihomoReady(client, server.URL, "synthetic-local-config.json") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("rules were visible but no configuration completion request arrived")
	}
	select {
	case err := <-done:
		t.Fatalf("returned before configuration completion: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if puts.Load() != 1 {
		t.Fatal("configuration transaction was retried")
	}
}

func TestVMessMihomoReadinessPreservesConfigurationFailure(t *testing.T) {
	var puts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/rules" {
			_, _ = w.Write([]byte(`{"rules":[{"Type":"Match","Proxy":"vmess-peer"}]}`))
			return
		}
		puts.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("synthetic response must not be exposed"))
	}))
	defer server.Close()
	if err := vmessMihomoReady(server.Client(), server.URL, "synthetic-local-config.json"); err == nil {
		t.Fatal("configuration failure was accepted as readiness")
	}
	if puts.Load() != 1 {
		t.Fatal("configuration failure was hidden by retry")
	}
}
