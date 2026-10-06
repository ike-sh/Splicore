package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/protocol/vless/wire"
)

// frameBoundaryConn commits a controlled prefix, then waits for an explicit
// deadline/close signal. No sleep or network timing determines the boundary.
type frameBoundaryConn struct {
	mu                      sync.Mutex
	data                    bytes.Buffer
	calls                   int
	firstN                  int // -1 means the complete frame
	firstErr                error
	block                   bool
	entered                 chan struct{}
	interrupted             chan struct{}
	closed                  chan struct{}
	deadlineOnce, closeOnce sync.Once
	closeCalls              atomic.Int64
}

func boundaryConn(n int, err error, block bool) *frameBoundaryConn {
	return &frameBoundaryConn{firstN: n, firstErr: err, block: block, entered: make(chan struct{}), interrupted: make(chan struct{}), closed: make(chan struct{})}
}
func (c *frameBoundaryConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	c.calls++
	first := c.calls == 1
	n := len(b)
	err := error(nil)
	if first {
		if c.firstN >= 0 {
			n = min(c.firstN, len(b))
		}
		err = c.firstErr
	}
	c.data.Write(b[:n])
	c.mu.Unlock()
	if first {
		close(c.entered)
		if c.block {
			select {
			case <-c.interrupted:
			case <-c.closed:
			}
			if err == nil && n != len(b) {
				err = os.ErrDeadlineExceeded
			}
		}
	}
	return n, err
}
func (c *frameBoundaryConn) snapshot() ([]byte, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.data.Bytes()), c.calls
}
func (c *frameBoundaryConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *frameBoundaryConn) Close() error {
	c.closeCalls.Add(1)
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *frameBoundaryConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *frameBoundaryConn) RemoteAddr() net.Addr            { return c.LocalAddr() }
func (c *frameBoundaryConn) SetDeadline(t time.Time) error   { return c.SetWriteDeadline(t) }
func (c *frameBoundaryConn) SetReadDeadline(time.Time) error { return nil }
func (c *frameBoundaryConn) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() && !t.After(time.Now()) {
		c.deadlineOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}

func TestClientPacketFrameCommitBoundaries(t *testing.T) {
	payload := []byte("payload-for-boundary")
	frame, err := wire.EncodeFrame(wire.Frame{Status: 1, Network: 2, Destination: packetDestination, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	header := len(frame) - len(payload)
	for _, tc := range []struct {
		name     string
		n        int
		err      error
		block    bool
		close    bool
		terminal bool
	}{
		{"zero-deadline-retry", 0, os.ErrDeadlineExceeded, true, false, false},
		{"one-header-byte-deadline", 1, os.ErrDeadlineExceeded, true, false, true},
		{"partial-header-close", 3, net.ErrClosed, true, true, true},
		{"full-header-partial-body", header + 1, io.ErrUnexpectedEOF, false, false, true},
		{"short-nil-error", 1, nil, false, false, true},
		{"complete", -1, nil, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := boundaryConn(tc.n, tc.err, tc.block)
			p := NewClientPacket(c, packetDestination)
			defer p.Close()
			result := make(chan error, 1)
			go func() { _, e := p.WriteTo(payload, nil); result <- e }()
			<-c.entered
			if tc.block {
				if tc.close {
					_ = p.Close()
				} else {
					_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
				}
			}
			e := awaitPacketWrite(t, result)
			if tc.n == -1 {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("incomplete frame succeeded")
			}
			_ = p.SetWriteDeadline(time.Time{})
			before, calls := c.snapshot()
			for range 8 {
				n, e := p.WriteTo(payload, nil)
				if tc.terminal {
					if n != 0 || !errors.Is(e, net.ErrClosed) {
						t.Fatalf("poisoned stream reused: %d %v", n, e)
					}
				} else if n != len(payload) || e != nil {
					t.Fatalf("valid retry/subsequent frame: %d %v", n, e)
				}
			}
			after, afterCalls := c.snapshot()
			if tc.terminal {
				if !bytes.Equal(before, after) || afterCalls != calls || c.closeCalls.Load() != 1 {
					t.Fatalf("tail write/double close: calls=%d/%d closes=%d", calls, afterCalls, c.closeCalls.Load())
				}
				if _, e := wire.ReadFrame(bytes.NewReader(after)); e == nil {
					t.Fatal("partial frame parsed as normal")
				}
			} else {
				r := bytes.NewReader(after)
				expected := 8
				if tc.n == -1 {
					expected++
				}
				for i := 0; i < expected; i++ {
					f, e := wire.ReadFrame(r)
					if e != nil || !bytes.Equal(f.Payload, payload) {
						t.Fatalf("frame %d: %+v %v", i, f, e)
					}
				}
				if r.Len() != 0 {
					t.Fatal("frame residue")
				}
			}
		})
	}
}

func TestClientPacketPartialParentCloseRace(t *testing.T) {
	for range 100 {
		c := boundaryConn(1, os.ErrDeadlineExceeded, true)
		p := NewClientPacket(c, packetDestination)
		result := make(chan error, 1)
		go func() { _, e := p.WriteTo([]byte("partial"), nil); result <- e }()
		<-c.entered
		var wg sync.WaitGroup
		wg.Go(func() { _ = p.SetWriteDeadline(time.Now().Add(-time.Second)) })
		wg.Go(func() { _ = p.Close() })
		wg.Go(func() { _ = p.Close() })
		wg.Wait()
		if e := awaitPacketWrite(t, result); e == nil {
			t.Fatal("partial commit succeeded")
		}
		if _, e := p.WriteTo([]byte("next"), nil); !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
		b, calls := c.snapshot()
		if len(b) != 1 || calls != 1 || c.closeCalls.Load() != 1 {
			t.Fatal("tail/double transition", len(b), calls, c.closeCalls.Load())
		}
	}
}

func TestPacketWriterCompletionAndTerminal(t *testing.T) {
	for _, mode := range []string{"not-admitted", "zero", "partial", "completed", "race"} {
		t.Run(mode, func(t *testing.T) {
			n := 1
			if mode == "zero" || mode == "not-admitted" {
				n = 0
			}
			if mode == "completed" {
				n = -1
			}
			c := boundaryConn(n, nil, true)
			parent, cancel := context.WithCancel(context.Background())
			w := newPacketWriter(parent, c, cancel)
			defer func() { w.retire(); <-w.done }()
			child, abort := context.WithCancelCause(parent)
			defer abort(nil)
			if mode == "not-admitted" {
				abort(os.ErrDeadlineExceeded)
				if e := w.send(child, []byte("frame")); !errors.Is(e, os.ErrDeadlineExceeded) {
					t.Fatal(e)
				}
				_, calls := c.snapshot()
				if calls != 0 {
					t.Fatal("canceled request admitted")
				}
				return
			}
			result := make(chan error, 1)
			go func() { result <- w.send(child, []byte("frame")) }()
			<-c.entered
			if mode == "race" {
				var wg sync.WaitGroup
				wg.Go(func() { abort(os.ErrDeadlineExceeded) })
				wg.Go(cancel)
				wg.Go(w.retire)
				wg.Wait()
			} else {
				abort(os.ErrDeadlineExceeded)
			}
			e := awaitPacketWrite(t, result)
			if mode == "completed" {
				if e != nil {
					t.Fatal("complete commit lost", e)
				}
			} else if e == nil {
				t.Fatal("incomplete frame succeeded")
			}
			before, calls := c.snapshot()
			if mode == "partial" || mode == "race" {
				if _, e := func() (int, error) { return 0, w.send(context.Background(), []byte("next")) }(); !errors.Is(e, net.ErrClosed) {
					t.Fatal(e)
				}
				after, nextCalls := c.snapshot()
				if !bytes.Equal(before, after) || calls != nextCalls || c.closeCalls.Load() != 1 {
					t.Fatal("tail/double retirement")
				}
			} else if e := w.send(context.Background(), []byte("next")); e != nil {
				t.Fatal("zero/complete stream failed sibling", e)
			}
		})
	}
}

func TestPacketsPartialCommitRetiresSharedParent(t *testing.T) {
	for _, mode := range []string{"deadline", "child-close", "parent-close"} {
		t.Run(mode, func(t *testing.T) {
			server, peer := net.Pipe()
			parent, cancel := context.WithCancel(context.Background())
			entered := make(chan *packetAssociation, 2)
			finished := make(chan error, 1)
			go func() {
				finished <- Packets(parent, server, wire.Request{Command: wire.Mux}, func(_ context.Context, p net.PacketConn) error {
					if _, _, e := p.ReadFrom(make([]byte, 64)); e != nil {
						return e
					}
					a := p.(*packetAssociation)
					entered <- a
					<-a.Context().Done()
					return nil
				})
			}()
			defer func() { cancel(); _ = peer.Close(); _ = awaitPacketWrite(t, finished) }()
			open := func(id uint16) *packetAssociation {
				t.Helper()
				if e := wire.WriteFrame(peer, wire.Frame{Session: id, Status: 1, Network: 2, Destination: packetDestination, Payload: []byte("activate")}); e != nil {
					t.Fatal(e)
				}
				return <-entered
			}
			a, b := open(1), open(2)
			result := make(chan error, 1)
			go func() {
				_, e := a.WriteTo([]byte("reply"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
				result <- e
			}()
			var prefix [1]byte
			if _, e := io.ReadFull(peer, prefix[:]); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "deadline":
				_ = a.SetWriteDeadline(time.Now().Add(-time.Second))
			case "child-close":
				_ = a.Close()
			case "parent-close":
				cancel()
			}
			if e := awaitPacketWrite(t, result); e == nil {
				t.Fatal("partial succeeded")
			}
			if _, e := b.WriteTo([]byte("sibling"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}); !errors.Is(e, net.ErrClosed) {
				t.Fatal("poisoned shared sibling survived", e)
			}
			if n, e := peer.Read(make([]byte, 64)); n != 0 || e == nil {
				t.Fatal("async tail", n, e)
			}
		})
	}
}

func TestVLESSResponseHeaderFailureIsTerminal(t *testing.T) {
	c := boundaryConn(1, os.ErrDeadlineExceeded, false)
	p := &Conn{Conn: c, Server: true}
	if _, e := p.Write([]byte("payload")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	if _, e := p.Write([]byte("next")); !errors.Is(e, net.ErrClosed) {
		t.Fatal(e)
	}
	b, calls := c.snapshot()
	if len(b) != 1 || calls != 1 {
		t.Fatal("header replay")
	}
}

func registrySize(r *packetRegistry) int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.entries) }
func makeRegistryQueue(ctx context.Context) *packetio.Queue {
	return packetio.New(ctx, &net.UDPAddr{}, func(context.Context, []byte, net.Addr) error { return nil })
}
func registryCycle(t *testing.T, shutdown bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := new(packetRegistry)
	register := func(id uint16) *packetAssociation {
		p, _, _, e := r.register(id, packetDestination, func() *packetio.Queue { return makeRegistryQueue(ctx) })
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	a, old, c := register(1), register(2), register(3)
	for _, sibling := range []*packetAssociation{a, c} {
		if _, e := sibling.WriteTo([]byte("sibling-traffic"), nil); e != nil {
			t.Fatal(e)
		}
	}
	old.Deliver([]byte("traffic"), &net.UDPAddr{})
	if _, _, e := old.ReadFrom(make([]byte, 16)); e != nil {
		t.Fatal(e)
	}
	// Suspend old.Close between cancel and unregister while replacing the key.
	_ = old.Queue.Close()
	var replacement *packetAssociation
	var regErr error
	var wg sync.WaitGroup
	wg.Go(func() { _ = old.Close(); _ = old.Close() })
	wg.Go(func() {
		replacement, _, _, regErr = r.register(2, packetDestination, func() *packetio.Queue { return makeRegistryQueue(ctx) })
	})
	if shutdown {
		wg.Go(r.close)
	}
	wg.Wait()
	if shutdown {
		if regErr != nil && !errors.Is(regErr, net.ErrClosed) {
			t.Fatal(regErr)
		}
		if registrySize(r) != 0 {
			t.Fatal("shutdown entries")
		}
		if a.Context().Err() == nil || c.Context().Err() == nil || (replacement != nil && replacement.Context().Err() == nil) {
			t.Fatal("shutdown did not close children")
		}
	} else {
		if regErr != nil || replacement == nil || replacement == old {
			t.Fatal("replacement", regErr)
		}
		if r.lookup(2) != replacement || r.lookup(1) != a || r.lookup(3) != c || registrySize(r) != 3 {
			t.Fatal("old close removed current owner/sibling")
		}
		_ = old.Close()
		_ = replacement.Close()
		if registrySize(r) != 2 {
			t.Fatal("unregister changed siblings")
		}
		if a.Context().Err() != nil || c.Context().Err() != nil {
			t.Fatal("sibling canceled")
		}
		for _, sibling := range []*packetAssociation{a, c} {
			if _, e := sibling.WriteTo([]byte("after-unregister"), nil); e != nil {
				t.Fatal(e)
			}
		}
		r.close()
		if registrySize(r) != 0 {
			t.Fatal("stale registry")
		}
	}
}
func TestPacketRegistryCompetition25000(t *testing.T) {
	for i := 0; i < 25000; i++ {
		registryCycle(t, i%17 == 0)
	}
	t.Log("cycles=25000 race=0 panic=0 deadlock=0 staleEntries=0")
}

func TestPacketsRegistryChurn10000(t *testing.T) {
	server, peer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	closed := make(chan *packetAssociation, 1)
	var active atomic.Int64
	var peakEntries, peakGoroutines atomic.Int64
	go func() {
		finished <- Packets(ctx, server, wire.Request{Command: wire.Mux}, func(_ context.Context, p net.PacketConn) error {
			active.Add(1)
			if _, _, e := p.ReadFrom(make([]byte, 64)); e != nil {
				active.Add(-1)
				return e
			}
			a := p.(*packetAssociation)
			peakEntries.Store(max(peakEntries.Load(), int64(registrySize(a.registry))))
			peakGoroutines.Store(max(peakGoroutines.Load(), int64(runtime.NumGoroutine())))
			_ = a.Close()
			active.Add(-1)
			closed <- a
			return nil
		})
	}()
	joined := false
	defer func() {
		cancel()
		_ = peer.Close()
		if !joined {
			_ = awaitPacketWrite(t, finished)
		}
	}()
	var r *packetRegistry
	t.Logf("Start active=0 registry=0 goroutines=%d pendingWriters=0", runtime.NumGoroutine())
	for id := 1; id <= 10000; id++ {
		if e := wire.WriteFrame(peer, wire.Frame{Session: uint16(id), Status: 1, Network: 2, Destination: packetDestination, Payload: []byte("activate")}); e != nil {
			t.Fatal("admit", id, e)
		}
		select {
		case p := <-closed:
			r = p.registry
		case <-time.After(time.Second):
			t.Fatal("churn stalled", id)
		}
		if registrySize(r) != 0 {
			t.Fatal("closed association retained", id, registrySize(r))
		}
		if id%1000 == 0 {
			t.Logf("Batch id=%d active=%d registry=%d goroutines=%d pendingWriters=0", id, active.Load(), registrySize(r), runtime.NumGoroutine())
		}
	}
	t.Logf("Peak registry=%d active=1 goroutines=%d pendingWriters=0", peakEntries.Load(), peakGoroutines.Load())
	cancel()
	_ = peer.Close()
	_ = awaitPacketWrite(t, finished)
	joined = true
	if active.Load() != 0 || registrySize(r) != 0 {
		t.Fatal("parent shutdown residue")
	}
	t.Logf("End active=%d registry=%d goroutines=%d pendingWriters=0 sessions=10000", active.Load(), registrySize(r), runtime.NumGoroutine())
}

func TestPacketRegistryClosePaths(t *testing.T) {
	for _, mode := range []string{"normal", "timeout", "peer", "creation-failure", "duplicate", "parent"} {
		t.Run(mode, func(t *testing.T) {
			r := new(packetRegistry)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, _, _, e := r.register(1, packetDestination, func() *packetio.Queue { return makeRegistryQueue(ctx) })
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "timeout":
				_ = p.SetReadDeadline(time.Now().Add(-time.Second))
				if _, _, e := p.ReadFrom(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
					t.Fatal(e)
				}
				_ = p.Close()
			case "peer":
				_ = r.lookup(1).Close()
			case "creation-failure":
				func() { defer p.Close() }()
			case "duplicate":
				_ = p.Close()
				_ = p.Close()
			case "parent":
				r.close()
			default:
				_ = p.Close()
			}
			if registrySize(r) != 0 {
				t.Fatal("entry retained", mode)
			}
		})
	}
}

// Opt-in duration gate keeps routine test runs fast. All loop iterations perform
// real local activation/traffic, registry cleanup, sibling and write-boundary
// races; duration is never simulated by sleeping.
func TestFix3LifecycleSoak10Minutes(t *testing.T) {
	seconds, e := strconv.Atoi(os.Getenv("SPLICORE_FIX3_LIFECYCLE_SECONDS"))
	if e != nil {
		t.Skip("explicit lifecycle duration required")
	}
	if seconds < 600 {
		t.Fatal(">=600 seconds required")
	}
	start := time.Now()
	end := start.Add(time.Duration(seconds) * time.Second)
	cycles := 0
	partial := 0
	before := runtime.NumGoroutine()
	t.Logf("Start registry=0 active=0 pendingWriters=0 goroutines=%d", before)
	for time.Now().Before(end) {
		registryCycle(t, cycles%17 == 0)
		cycles++
		if cycles%100 == 0 {
			c := boundaryConn(1, os.ErrDeadlineExceeded, true)
			ctx, cancel := context.WithCancel(context.Background())
			w := newPacketWriter(ctx, c, cancel)
			child, abort := context.WithCancelCause(ctx)
			result := make(chan error, 1)
			go func() { result <- w.send(child, []byte("partial-frame")) }()
			<-c.entered
			var wg sync.WaitGroup
			wg.Go(func() { abort(os.ErrDeadlineExceeded) })
			wg.Go(cancel)
			wg.Go(w.retire)
			wg.Wait()
			if e := awaitPacketWrite(t, result); e == nil {
				t.Fatal("partial success")
			}
			<-w.done
			b, calls := c.snapshot()
			if len(b) != 1 || calls != 1 || c.closeCalls.Load() != 1 {
				t.Fatal("tail/transition")
			}
			partial++
		}
		if cycles%25000 == 0 {
			runtime.GC()
			t.Logf("Batch elapsed=%s cycles=%d partialRaces=%d registry=0 active=0 pendingWriters=0 goroutines=%d", time.Since(start), cycles, partial, runtime.NumGoroutine())
		}
	}
	runtime.GC()
	t.Logf("End duration=%s cycles=%d partialRaces=%d registry=0 active=0 pendingWriters=0 goroutines=%d unexpectedErrors=0", time.Since(start), cycles, partial, runtime.NumGoroutine())
	if runtime.NumGoroutine() > before+2 {
		t.Fatal("goroutine residue")
	}
}
