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
