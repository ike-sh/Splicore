package relay

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
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
)

type lifecycleConn struct {
	net.Conn
	dst                        access.Endpoint
	input                      chan []byte
	fail, stopped, started     chan struct{}
	startOnce                  sync.Once
	closes                     atomic.Int32
	writes                     atomic.Int32
	active                     *atomic.Int64
	closeEntered, closeRelease chan struct{}
}

func (c *lifecycleConn) Read(b []byte) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	select {
	case <-c.fail:
		return 0, errors.New("synthetic terminal read failure")
	case <-c.stopped:
		return 0, net.ErrClosed
	case v := <-c.input:
		return copy(b, v), nil
	}
}
func (c *lifecycleConn) Write(b []byte) (int, error) {
	select {
	case <-c.stopped:
		return 0, net.ErrClosed
	default:
	}
	c.writes.Add(1)
	select {
	case c.input <- bytes.Clone(b):
		return len(b), nil
	case <-c.stopped:
		return 0, net.ErrClosed
	}
}
func (c *lifecycleConn) Close() error {
	if c.closes.Add(1) != 1 {
		panic("socket closed more than once")
	}
	close(c.stopped)
	if c.active != nil {
		c.active.Add(-1)
	}
	if c.closeEntered != nil {
		close(c.closeEntered)
		<-c.closeRelease
	}
	return nil
}
func (c *lifecycleConn) RemoteAddr() net.Addr { return netaddr.UDP(c.dst) }
func lifeWait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(3 * time.Second):
		t.Fatal("lifecycle barrier timed out")
	}
}
func lifeRecv(t *testing.T, c <-chan []byte, want []byte) {
	t.Helper()
	select {
	case b := <-c:
		if !bytes.Equal(b, want) {
			t.Fatalf("reply %q want %q", b, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("actual reply not forwarded")
	}
}

type lifeFixture struct {
	p       *packetRelay
	q       *packetio.Queue
	replies chan []byte
	created []*lifecycleConn
	active  atomic.Int64
}

func newLife(t *testing.T, idle time.Duration) *lifeFixture {
	t.Helper()
	f := &lifeFixture{replies: make(chan []byte, 256)}
	f.q = packetio.New(context.Background(), &net.UDPAddr{}, func(_ context.Context, b []byte, _ net.Addr) error { f.replies <- bytes.Clone(b); return nil })
	f.p = newPacketRelay(f.q, func(_ context.Context, d access.Endpoint) (net.Conn, error) {
		c := &lifecycleConn{dst: d, input: make(chan []byte, 8), fail: make(chan struct{}), stopped: make(chan struct{}), started: make(chan struct{}), active: &f.active}
		f.active.Add(1)
		f.created = append(f.created, c)
		return c, nil
	}, idle)
	t.Cleanup(f.p.shutdown)
	return f
}

var lifeKey = access.Endpoint{Host: "127.0.0.1", Port: 53}

func lifeOwner(t *testing.T, p *packetRelay, k access.Endpoint) *packetTarget {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.targets[k]
	if v == nil {
		t.Fatal("missing active owner")
	}
	return v
}
func lifeEmpty(t *testing.T, p *packetRelay) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.targets) != 0 {
		t.Fatalf("registry residue %d", len(p.targets))
	}
}
func lifeWrite(t *testing.T, f *lifeFixture, k access.Endpoint, b []byte) {
	t.Helper()
	if err := f.p.write(context.Background(), k, b); err != nil {
		t.Fatal(err)
	}
	lifeRecv(t, f.replies, b)
}
func lifeDeadline(p *packetRelay, o *packetTarget) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return o.last.Add(p.idle)
}

func TestPacketTargetReaderExitRecovery(t *testing.T) {
	f := newLife(t, time.Hour)
	lifeWrite(t, f, lifeKey, []byte("first"))
	a := lifeOwner(t, f.p, lifeKey)
	lifeWait(t, a.conn.(*lifecycleConn).started)
	close(a.conn.(*lifecycleConn).fail)
	lifeWait(t, a.readerDone)
	lifeWait(t, a.idleDone)
	lifeEmpty(t, f.p)
	if a.conn.(*lifecycleConn).closes.Load() != 1 {
		t.Fatal("socket not released")
	}
	for i := range 8 {
		lifeWrite(t, f, lifeKey, []byte{byte(i)})
	}
	b := lifeOwner(t, f.p, lifeKey)
	if a == b || len(f.created) != 2 {
		t.Fatal("same-key replacement absent")
	}
	f.p.shutdown()
	lifeEmpty(t, f.p)
	lifeWait(t, b.readerDone)
}
func TestPacketTargetIdleExpiry(t *testing.T) {
	f := newLife(t, 30*time.Millisecond)
	lifeWrite(t, f, lifeKey, []byte("expire"))
	a := lifeOwner(t, f.p, lifeKey)
	lifeWait(t, a.idleDone)
	lifeWait(t, a.readerDone)
	lifeEmpty(t, f.p)
	if a.conn.(*lifecycleConn).closes.Load() != 1 || f.active.Load() != 0 {
		t.Fatal("idle socket retained")
	}
	lifeWrite(t, f, lifeKey, []byte("recreate"))
	if lifeOwner(t, f.p, lifeKey) == a {
		t.Fatal("expired owner reused")
	}
}
func TestPacketTargetActivityRefresh(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			f := newLife(t, time.Hour)
			lifeWrite(t, f, lifeKey, []byte("first"))
			a := lifeOwner(t, f.p, lifeKey)
			old := time.Now().Add(-time.Nanosecond)
			f.p.mu.Lock()
			a.last = old.Add(-f.p.idle)
			f.p.mu.Unlock()
			if direction == "outbound" {
				lifeWrite(t, f, lifeKey, []byte("refresh"))
			} else {
				a.conn.(*lifecycleConn).input <- []byte("refresh")
				lifeRecv(t, f.replies, []byte("refresh"))
			}
			if expired, _ := f.p.expire(a, old); expired {
				t.Fatal("activity failed to refresh")
			}
			if expired, _ := f.p.expire(a, lifeDeadline(f.p, a)); !expired {
				t.Fatal("eventual idle did not expire")
			}
			lifeWait(t, a.readerDone)
			lifeWait(t, a.idleDone)
			lifeEmpty(t, f.p)
		})
	}
}
func TestPacketTargetSameKeyDelayedCleanup(t *testing.T) {
	f := newLife(t, time.Hour)
	lifeWrite(t, f, lifeKey, []byte("A"))
	a := lifeOwner(t, f.p, lifeKey)
	c := a.conn.(*lifecycleConn)
	c.closeEntered = make(chan struct{})
	c.closeRelease = make(chan struct{})
	done := make(chan struct{})
	go func() { f.p.retire(a); close(done) }()
	lifeWait(t, c.closeEntered) // detached, socket Close still blocked; parent lock is free
	lifeWrite(t, f, lifeKey, []byte("B"))
	b := lifeOwner(t, f.p, lifeKey)
	if a == b {
		t.Fatal("old owner reused")
	}
	close(c.closeRelease)
	lifeWait(t, done)
	lifeWait(t, a.readerDone)
	lifeWait(t, a.idleDone)
	f.p.retire(a)
	f.p.expire(a, time.Now().Add(2*time.Hour))
	if lifeOwner(t, f.p, lifeKey) != b {
		t.Fatal("old cleanup/timer deleted B")
	}
	lifeWrite(t, f, lifeKey, []byte("B survives"))
}
func TestPacketTargetSiblingAndUserIsolation(t *testing.T) {
	f := newLife(t, time.Hour)
	other := newLife(t, time.Hour)
	sibling := lifeKey
	sibling.Port++
	lifeWrite(t, f, lifeKey, []byte("A"))
	a := lifeOwner(t, f.p, lifeKey)
	lifeWrite(t, f, sibling, []byte("sibling"))
	lifeWrite(t, other, lifeKey, []byte("other account"))
	f.p.expire(a, lifeDeadline(f.p, a))
	lifeWait(t, a.readerDone)
	for range 4 {
		lifeWrite(t, f, sibling, []byte("sibling alive"))
		lifeWrite(t, other, lifeKey, []byte("other account alive"))
	}
	if len(f.created) != 2 || len(other.created) != 1 {
		t.Fatal("isolation redialed sibling/user")
	}
}
func TestPacketTargetRegistryBound(t *testing.T) {
	f := newLife(t, time.Hour)
	owners := []*packetTarget{}
	for i := range 128 {
		k := lifeKey
		k.Port = uint16(1000 + i)
		lifeWrite(t, f, k, []byte{byte(i)})
		owners = append(owners, lifeOwner(t, f.p, k))
	}
	k := lifeKey
	k.Port = 2000
	if _, err := f.p.target(context.Background(), k); err == nil {
		t.Fatal("128 cap missing")
	}
	for _, a := range owners {
		f.p.expire(a, lifeDeadline(f.p, a))
		lifeWait(t, a.readerDone)
		lifeWait(t, a.idleDone)
	}
	lifeEmpty(t, f.p)
	lifeWrite(t, f, k, []byte("capacity recovered"))
}
func TestPacketTargetCompetition(t *testing.T) {
	const cycles = 1000
	for i := range cycles {
		f := newLife(t, time.Hour)
		lifeWrite(t, f, lifeKey, []byte("race"))
		a := lifeOwner(t, f.p, lifeKey)
		deadline := lifeDeadline(f.p, a)
		start := make(chan struct{})
		var wg sync.WaitGroup
		tasks := []func(){func() { f.p.retire(a) }, func() { f.p.expire(a, deadline) }, func() { close(a.conn.(*lifecycleConn).fail) }}
		if i%2 == 0 {
			tasks = append(tasks, f.p.shutdown)
		} else {
			tasks = append(tasks, func() { _ = f.p.write(context.Background(), lifeKey, []byte("boundary")) })
		}
		for _, task := range tasks {
			wg.Add(1)
			go func(task func()) { defer wg.Done(); <-start; task() }(task)
		}
		close(start)
		wg.Wait()
		f.p.shutdown()
		lifeWait(t, a.readerDone)
		lifeWait(t, a.idleDone)
		lifeEmpty(t, f.p)
		if f.active.Load() != 0 {
			t.Fatal("active sockets after shutdown")
		}
		if _, err := f.p.target(context.Background(), lifeKey); !errors.Is(err, net.ErrClosed) {
			t.Fatal("registered after closing")
		}
	}
	t.Logf("competition cycles=%d close/expiry/reader-exit/parent-close/new-write unexpected=0", cycles)
}
func TestPacketTargetShutdownDuringDial(t *testing.T) {
	f := newLife(t, time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	original := f.p.dial
	f.p.dial = func(ctx context.Context, k access.Endpoint) (net.Conn, error) {
		close(entered)
		<-release
		return original(ctx, k)
	}
	done := make(chan error, 1)
	go func() { _, err := f.p.target(context.Background(), lifeKey); done <- err }()
	lifeWait(t, entered)
	f.p.shutdown()
	close(release)
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	lifeEmpty(t, f.p)
	if f.active.Load() != 0 {
		t.Fatal("dial completion leaked")
	}
}
func TestPacketTargetChurn10000(t *testing.T) {
	const cycles = 10000
	f := newLife(t, time.Hour)
	startG := runtime.NumGoroutine()
	peakG := startG
	fd := func() int {
		v, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return -1
		}
		return len(v)
	}
	startFD := fd()
	peakTargets := 0
	expired, exited, retired, recreated := 0, 0, 0, 0
	begin := time.Now()
	sample := func(i int) {
		f.p.mu.Lock()
		n := len(f.p.targets)
		f.p.mu.Unlock()
		peakTargets = max(peakTargets, n)
		g := runtime.NumGoroutine()
		peakG = max(peakG, g)
		t.Logf("cycles=%d active_targets=%d registry=%d goroutines=%d fd=%d pending_writes=0", i, f.active.Load(), n, g, fd())
	}
	for i := range cycles {
		k := lifeKey
		k.Port = uint16(1000 + i%128)
		lifeWrite(t, f, k, []byte{byte(i), byte(i >> 8)})
		a := lifeOwner(t, f.p, k)
		if i%1000 == 0 {
			sample(i)
		}
		switch i % 3 {
		case 0:
			f.p.expire(a, lifeDeadline(f.p, a))
			expired++
		case 1:
			close(a.conn.(*lifecycleConn).fail)
			exited++
		case 2:
			f.p.retire(a)
			retired++
		}
		lifeWait(t, a.readerDone)
		lifeWait(t, a.idleDone)
		lifeEmpty(t, f.p)
		lifeWrite(t, f, k, []byte("replacement reply"))
		b := lifeOwner(t, f.p, k)
		recreated++
		if a == b {
			t.Fatal("stale reuse")
		}
		f.p.retire(b)
		lifeWait(t, b.readerDone)
		lifeWait(t, b.idleDone)
	}
	f.p.shutdown()
	lifeEmpty(t, f.p)
	runtime.GC()
	sample(cycles)
	if f.active.Load() != 0 || fd() != startFD {
		t.Fatal("resource residue")
	}
	t.Logf("focused lifecycle duration=%s cycles=%d created=%d expirations=%d forced_reader_exits=%d explicit_retirements=%d recreations=%d expected_terminal_events=%d unexpected=0 peak_targets=%d final_targets=0 final_readers=0 stale_entries=0 goroutines_start=%d sampled_peak=%d end=%d fd_start=%d end=%d sockets=controlled-test-connections", time.Since(begin), cycles, len(f.created), expired, exited, retired, recreated, cycles+recreated, peakTargets, startG, peakG, runtime.NumGoroutine(), startFD, fd())
}

// Parent cancellation must unblock a target Write, rather than waiting for the
// main packet loop to reach its next ReadFrom before sockets can be closed.
type cancelWriteConn struct {
	net.Conn
	started, stop chan struct{}
	once          sync.Once
}

func (c *cancelWriteConn) Read([]byte) (int, error) { <-c.stop; return 0, net.ErrClosed }
func (c *cancelWriteConn) Write([]byte) (int, error) {
	close(c.started)
	<-c.stop
	return 0, net.ErrClosed
}
func (c *cancelWriteConn) Close() error         { c.once.Do(func() { close(c.stop) }); return nil }
func (c *cancelWriteConn) RemoteAddr() net.Addr { return netaddr.UDP(lifeKey) }
func TestPacketTargetContextCancellationBlockedWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := packetio.New(context.Background(), netaddr.UDP(lifeKey), func(context.Context, []byte, net.Addr) error { return nil })
	c := &cancelWriteConn{started: make(chan struct{}), stop: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		_ = Packets(ctx, q, func(context.Context, access.Endpoint) (net.Conn, error) { return c, nil }, 0)
		close(done)
	}()
	q.Deliver([]byte("blocked"), netaddr.UDP(lifeKey))
	lifeWait(t, c.started)
	cancel()
	lifeWait(t, done)
	lifeWait(t, c.stop)
	f := newLife(t, time.Hour)
	lifeWrite(t, f, lifeKey, []byte("active"))
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := f.p.target(canceled, lifeKey); !errors.Is(err, net.ErrClosed) {
		t.Fatal("canceled lookup reused active socket")
	}
}
