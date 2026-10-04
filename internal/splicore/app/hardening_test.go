package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/transport"
)

func TestPhase15HTTPShutdownJoinsApplicationRequests(t *testing.T) {
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelDeadline()
	ctx, cancel := context.WithCancel(deadline)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server := transport.Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
	}))
	serving := make(chan error, 1)
	go func() { serving <- serveHTTP(ctx, server, listener, func() error { return nil }) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		r, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			r.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-deadline.Done():
		t.Fatal("handler never entered")
	}
	cancel()
	select {
	case <-canceled:
	case <-deadline.Done():
		t.Fatal("request did not inherit daemon cancellation")
	}
	select {
	case err := <-serving:
		t.Fatal("daemon returned before application handler", err)
	default:
	}
	release <- struct{}{}
	select {
	case err := <-serving:
		if err != nil {
			t.Fatal(err)
		}
	case <-deadline.Done():
		t.Fatal("shutdown did not join")
	}
	select {
	case <-clientDone:
	case <-deadline.Done():
		t.Fatal("client leaked")
	}
}

func TestPhase15ForcedHTTPShutdownStillJoinsHandler(t *testing.T) {
	deadline, cancelDeadline := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelDeadline()
	ctx, cancel := context.WithCancel(deadline)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	entered := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	server := transport.Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release }))
	serving := make(chan error, 1)
	go func() { serving <- serveHTTP(ctx, server, listener, func() error { return nil }) }()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		r, err := http.Get("http://" + listener.Addr().String())
		if err == nil {
			r.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-deadline.Done():
		t.Fatal("handler never entered")
	}
	cancel()
	// A connection close is the observable barrier for the graceful deadline.
	select {
	case <-clientDone:
	case <-deadline.Done():
		t.Fatal("force Close did not terminate connection")
	}
	select {
	case err := <-serving:
		t.Fatal("forced close released application before handler", err)
	default:
	}
	release <- struct{}{}
	select {
	case err := <-serving:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("shutdown failure discarded", err)
		}
	case <-deadline.Done():
		t.Fatal("handler not joined")
	}
}

func TestPhase15ReadinessFailureJoinsShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fault := errors.New("synthetic readiness failure")
	server := transport.Server(http.NotFoundHandler())
	if err = serveHTTP(ctx, server, listener, func() error { cancel(); return fault }); !errors.Is(err, fault) {
		t.Fatal(err)
	}
}
