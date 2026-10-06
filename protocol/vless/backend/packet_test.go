package backend

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

type observedPacketWrite struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (c *observedPacketWrite) Write(b []byte) (int, error) {
	c.once.Do(func() { close(c.started) })
	return c.Conn.Write(b)
}
func awaitPacketWrite(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(time.Second):
		t.Fatal("write/shutdown did not finish")
		return nil
	}
}

var packetDestination = access.Endpoint{Host: "127.0.0.1", Port: 12345}

func TestPacketsAssociationIsolationAndOwnedFrame(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "parent"} {
		t.Run(mode, func(t *testing.T) {
			raw, client := net.Pipe()
			server := &observedPacketWrite{Conn: raw, started: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			entered := make(chan net.PacketConn, 2)
			parent := make(chan error, 1)
			go func() {
				parent <- Packets(ctx, server, wire.Request{Command: wire.Mux}, func(ctx context.Context, p net.PacketConn) error {
					if _, _, err := p.ReadFrom(make([]byte, 64)); err != nil {
						return err
					}
					entered <- p
					<-ctx.Done()
					return ctx.Err()
				})
			}()
			defer func() { cancel(); _ = client.Close(); _ = server.Close(); _ = awaitPacketWrite(t, parent) }()
			open := func(id uint16) net.PacketConn {
				t.Helper()
				if err := wire.WriteFrame(client, wire.Frame{Session: id, Status: 1, Network: 2, Destination: packetDestination, Payload: []byte("request")}); err != nil {
					t.Fatal(err)
				}
				return <-entered
			}
			a, b := open(1), open(2)
			scratch := []byte("immutable-reply")
			resultA := make(chan error, 1)
			go func() {
				_, err := a.WriteTo(scratch, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
				resultA <- err
			}()
			<-server.started
			switch mode {
			case "close":
				if err := wire.WriteFrame(client, wire.Frame{Session: 1, Status: 3}); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				_ = a.SetWriteDeadline(time.Now().Add(-time.Second))
			case "parent":
				_ = client.Close()
			}
			err := awaitPacketWrite(t, resultA)
			want := net.ErrClosed
			if mode == "deadline" {
				want = os.ErrDeadlineExceeded
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v want %v", err, want)
			}
			clear(scratch) // no admitted wire write remains after caller returns.
			if mode == "parent" {
				// Use a valid address while parent cancellation is propagating:
				// argument validation must not mask the transport-close assertion.
				if _, err := b.WriteTo([]byte("sibling"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}); !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
				return
			}
			// No bytes were consumed from the canceled frame. Its Write is joined
			// before returning, so siblings can use the unchanged frame boundary.
			read := make(chan error, 1)
			go func() {
				for _, payload := range []string{"sibling", "ordered-next"} {
					f, err := wire.ReadFrame(client)
					if err == nil && (string(f.Payload) != payload || f.Session != 2) {
						err = wire.ErrFrame
					}
					if err != nil {
						read <- err
						return
					}
				}
				read <- nil
			}()
			for _, payload := range []string{"sibling", "ordered-next"} {
				if _, err := b.WriteTo([]byte(payload), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}); err != nil {
					t.Fatal(err)
				}
			}
			if err := awaitPacketWrite(t, read); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPacketWriterBoundedOwnershipAndJoin(t *testing.T) {
	fdCount := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return len(entries)
	}
	beforeG, beforeFD := runtime.NumGoroutine(), fdCount()
	raw, client := net.Pipe()
	server := &observedPacketWrite{Conn: raw, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	w := newPacketWriter(ctx, server, cancel)
	defer func() { cancel(); _ = client.Close(); _ = server.Close(); <-w.done }()
	var active atomic.Int64
	makeQueue := func() *packetio.Queue {
		active.Add(1)
		return packetio.New(ctx, server.LocalAddr(), func(ctx context.Context, b []byte, _ net.Addr) error {
			return w.send(ctx, bytes.Clone(b))
		})
	}
	a := makeQueue()
	result := make(chan error, 1)
	go func() { _, err := a.WriteTo([]byte("owned-frame"), nil); result <- err }()
	<-server.started
	t.Logf("Before goroutines=%d FD=%d pending=0 associations=0", beforeG, beforeFD)
	t.Logf("Blocked goroutines=%d FD=%d pending=%d associations=%d parent_inflight=1", runtime.NumGoroutine(), fdCount(), len(w.requests), active.Load())
	_ = a.Close()
	if err := awaitPacketWrite(t, result); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	active.Add(-1)
	// Churn zero-commit canceled requests on the same parent. Each actual Write
	// joins before returning, with no buffered entry or asynchronous tail.
	for range 128 {
		q := makeQueue()
		if err := q.SetWriteDeadline(time.Now().Add(1 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := q.WriteTo([]byte("never-handed-off"), nil); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
		_ = q.Close()
		active.Add(-1)
	}
	if cap(w.requests) != 0 || len(w.requests) != 0 || active.Load() != 0 {
		t.Fatal("unbounded/retained request state")
	}
	t.Logf("AfterClose goroutines=%d FD=%d pending=%d associations=%d parent_inflight=0", runtime.NumGoroutine(), fdCount(), len(w.requests), active.Load())
	cancel()
	_ = server.Close()
	_ = client.Close()
	joined := make(chan error, 1)
	go func() { <-w.done; joined <- nil }()
	_ = awaitPacketWrite(t, joined)
	finalG, finalFD := runtime.NumGoroutine(), fdCount()
	// A done-channel receive confirms completion, but runtime.NumGoroutine can
	// still count the notifying goroutine until its return is scheduled. Observe
	// quiescence within the existing one-second lifecycle bound; retain the same
	// baseline assertion so an actual retained worker still fails this test.
	until := time.Now().Add(time.Second)
	for finalG > beforeG+1 && time.Now().Before(until) {
		runtime.Gosched()
		finalG, finalFD = runtime.NumGoroutine(), fdCount()
	}
	t.Logf("Final goroutines=%d FD=%d pending=%d associations=%d parent_inflight=0 joined=true", finalG, finalFD, len(w.requests), active.Load())
	if beforeFD >= 0 && finalFD != beforeFD {
		t.Fatal("FD residue")
	}
	// A timer callback may be completing; all owned write workers are joined.
	if finalG > beforeG+1 {
		t.Fatalf("goroutine residue %d -> %d", beforeG, finalG)
	}
}
