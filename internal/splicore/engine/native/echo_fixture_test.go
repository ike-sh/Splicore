package native

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Every endpoint is owned by this test and bound to loopback. Cleanup closes
// accepted sockets and joins all workers; no retry or timing workaround is used.
func vlessEcho(t *testing.T, tlsConfig *tls.Config) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig != nil {
		l = tls.NewListener(l, tlsConfig)
	}
	var access sync.Mutex
	connections := map[net.Conn]bool{}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			access.Lock()
			connections[c] = true
			workers.Add(1)
			access.Unlock()
			go func() {
				defer workers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(15 * time.Second))
				_, _ = io.Copy(c, c)
				access.Lock()
				delete(connections, c)
				access.Unlock()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		access.Lock()
		for c := range connections {
			_ = c.Close()
		}
		access.Unlock()
		workers.Wait()
	})
	return l
}

// The fixture must be usable even when the optional REALITY tests are excluded.
func TestDefaultVLESSEchoFixtureLifecycle(t *testing.T) {
	t.Run("active-connection-cleanup", func(t *testing.T) {
		var peer net.Conn
		var address string
		if !t.Run("owner", func(t *testing.T) {
			listener := vlessEcho(t, nil)
			address = listener.Addr().String()
			var err error
			peer, err = net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if t.Failed() {
					peer.Close()
				}
			}()
			peer.SetDeadline(time.Now().Add(time.Second))
			if _, err = peer.Write([]byte("fixture")); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len("fixture"))
			if _, err = io.ReadFull(peer, got); err != nil || string(got) != "fixture" {
				t.Fatal("echo integrity", string(got), err)
			}
			// Keep the client open: the owner's Cleanup must interrupt its worker.
		}) {
			return
		}
		defer peer.Close()
		peer.SetReadDeadline(time.Now().Add(time.Second))
		_, err := peer.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("fixture connection survived owner cleanup")
		}
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			t.Fatal("fixture cleanup left a blocked connection", err)
		}
		if extra, err := net.DialTimeout("tcp", address, time.Second); err == nil {
			extra.Close()
			t.Fatal("fixture listener survived owner cleanup")
		}
	})
	t.Run("invalid-tls-client", func(t *testing.T) {
		listener := vlessEcho(t, &tls.Config{MinVersion: tls.VersionTLS13})
		peer, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(time.Second))
		if _, err = peer.Write([]byte("invalid TLS record")); err != nil {
			t.Fatal(err)
		}
		if _, err = peer.Read(make([]byte, 1)); err == nil {
			t.Fatal("invalid TLS client was accepted")
		}
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			t.Fatal("failed TLS handshake left a blocked connection", err)
		}
	})
}
