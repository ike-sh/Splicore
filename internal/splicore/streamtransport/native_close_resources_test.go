//go:build with_quic

package streamtransport

import (
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestPhase31CloseResourceCycles(t *testing.T) {
	before := runtime.NumGoroutine()
	fds := func() int {
		entries, e := os.ReadDir("/proc/self/fd")
		if e != nil {
			return -1
		}
		return len(entries)
	}
	beforeFD := fds()
	for round := range 3 {
		t.Run(string(rune('A'+round)), func(t *testing.T) {
			// Each nested test's cleanup waits for the transport owner and its workers.
			t.Run("quic", TestPhase31QUICBlockedWriteFullClose)
			t.Run("http", TestPhase31HTTPNetworkWriteCancellation)
			for _, kind := range []string{"http", "h2", "quic-stream"} {
				t.Run(kind, func(t *testing.T) {
					var cl *Client
					var l net.Listener
					if kind == "quic-stream" {
						cl, l, _ = quicFixture(t)
					} else {
						cl, l, _ = httpFixture(t, kind)
					}
					a, e := cl.DialContext(t.Context())
					if e != nil {
						t.Fatal(e)
					}
					if kind == "quic-stream" {
						if _, e = a.Write([]byte{1}); e != nil {
							t.Fatal(e)
						}
					}
					b, e := l.Accept()
					if e != nil {
						t.Fatal(e)
					}
					if kind == "quic-stream" {
						if _, e = io.ReadFull(b, make([]byte, 1)); e != nil {
							t.Fatal(e)
						}
					}
					a.Close()
					b.Close()
					cl.Close()
					l.Close()
					switch impl := cl.impl.(type) {
					case *quicNativeClient:
						impl.mu.Lock()
						active, pending := len(impl.streams), impl.pending
						conn := impl.conn
						impl.mu.Unlock()
						if active != 0 || pending != 0 || conn != nil {
							t.Fatal("QUIC ownership retained", active, pending, conn)
						}
					case *httpNativeClient:
						impl.mu.Lock()
						active, pending, sockets := len(impl.streams), impl.pending, len(impl.sockets)
						impl.mu.Unlock()
						if active != 0 || pending != 0 || sockets != 0 {
							t.Fatal("HTTP ownership retained", active, pending, sockets)
						}
						listener := l.(*httpNativeListener)
						listener.mu.Lock()
						active, sockets = len(listener.streams), len(listener.sockets)
						listener.mu.Unlock()
						if active != 0 || sockets != 0 {
							t.Fatal("HTTP server ownership retained", active, sockets)
						}
					}
				})
			}
		})
		// Bounded stable observation permits runtime background workers and cached
		// descriptors. It checks convergence over three samples, not exact deltas.
		ticker := time.NewTicker(20 * time.Millisecond)
		deadline := time.NewTimer(3 * time.Second)
		stable := 0
	observe:
		for {
			select {
			case <-ticker.C:
				runtime.GC()
				goroutines, fd := runtime.NumGoroutine(), fds()
				if goroutines <= before+8 && (beforeFD < 0 || fd <= beforeFD+4) {
					stable++
				} else {
					stable = 0
				}
				if stable == 3 {
					t.Logf("round %d stable: goroutines %d -> %d; FD %d -> %d", round, before, goroutines, beforeFD, fd)
					break observe
				}
			case <-deadline.C:
				t.Fatalf("resources did not converge: goroutines %d -> %d; FD %d -> %d", before, runtime.NumGoroutine(), beforeFD, fds())
			}
		}
		ticker.Stop()
		deadline.Stop()
	}
}
