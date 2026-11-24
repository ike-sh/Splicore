package backend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The barriers wrap real operations, not their return values. In particular,
// stop is gated after terminate has committed its local closed state.
func TestNaiveCloseWriteDuringFullCleanup(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = "off" }, nil)
			conn, err := client.Open(context.Background(), echoTarget(t, "tcp", "127.0.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw := conn.(*pooledStream).raw.(*bodyConn)
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var calls atomic.Int32
			raw.mu.Lock()
			stop, finishWrite := raw.stop, raw.closeWrite
			raw.stop = func(graceful bool) { close(entered); <-release; stop(graceful) }
			raw.closeWrite = func() error { calls.Add(1); return finishWrite() }
			raw.mu.Unlock()
			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			halfCloseWait(t, entered)
			if e := conn.(interface{ CloseWrite() error }).CloseWrite(); !errors.Is(e, net.ErrClosed) {
				t.Errorf("CloseWrite during committed Close = %T %v, want net.ErrClosed", e, e)
			}
			if n := calls.Load(); n != 0 {
				t.Errorf("late CloseWrite reached the real transport %d time(s)", n)
			}
			unblock()
			halfCloseResult(t, closed)
		})
	}
}

func TestNaiveCloseWriteAfterCarrierFailure(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, server := startTestServer(t, mode)
			client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = "off" }, nil)
			conn, err := client.Open(t.Context(), echoTarget(t, "tcp", "127.0.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err = server.Close(ctx); err != nil {
				t.Fatal(err)
			}
			// The remote connection is genuinely dead, but the application's local
			// stream has not called Close, so only the carrier can reject CloseWrite.
			raw := conn.(*pooledStream).raw.(*bodyConn)
			halfCloseWait(t, raw.pumpDone)
			var b [1]byte
			if _, err = conn.Read(b[:]); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("wanted a real transport failure, got %T %v", err, err)
			}
			if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err == nil {
				t.Fatal("CloseWrite reported success after carrier shutdown")
			} else {
				t.Logf("CloseWrite preserved a carrier failure: %T", err)
			}
		})
	}
}

// A full Close must bypass wmu even while a real transport write invocation is
// outstanding and CloseWrite is queued behind it.
func TestNaiveCloseInterruptsPendingWriteAndHalfClose(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = "off" }, nil)
			conn, err := client.Open(t.Context(), echoTarget(t, "tcp", "127.0.0.1:0"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			raw := conn.(*pooledStream).raw.(*bodyConn)
			p := &naiveWriteGate{Writer: raw.w, entered: make(chan struct{}), release: make(chan struct{})}
			raw.w = p
			unblock := sync.OnceFunc(func() { close(p.release) })
			defer unblock()
			write, half, closed := make(chan error, 1), make(chan error, 1), make(chan error, 1)
			go func() { _, e := conn.Write([]byte("outstanding payload")); write <- e }()
			halfCloseWait(t, p.entered)
			go func() { half <- conn.(interface{ CloseWrite() error }).CloseWrite() }()
			go func() { closed <- conn.Close() }()
			halfCloseResult(t, closed)
			unblock()
			select {
			case err := <-write:
				if err == nil {
					t.Error("outstanding Write reported success after Close")
				}
			case <-t.Context().Done():
				t.Fatal("write not joined")
			}
			select {
			case err := <-half:
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("queued CloseWrite after Close = %T %v", err, err)
				}
			case <-t.Context().Done():
				t.Fatal("half-close not joined")
			}
		})
	}
}

type naiveWriteGate struct {
	io.Writer
	entered, release chan struct{}
}

type naivePostReadCleanupGate struct {
	readEntered, releaseRead, closeEntered, releaseClose, closeDone chan struct{}
	readOnce, closeOnce                                             sync.Once
}

func (r *naivePostReadCleanupGate) Read(p []byte) (int, error) {
	r.readOnce.Do(func() { close(r.readEntered) })
	// Model transportResponseBody.Read after it consumed response DATA but
	// before it returns from the connection-wide WINDOW_UPDATE write lock.
	<-r.releaseRead
	return 0, net.ErrClosed
}
func (r *naivePostReadCleanupGate) Close() error {
	r.closeOnce.Do(func() {
		close(r.closeEntered)
		<-r.releaseClose
		close(r.closeDone)
	})
	return nil
}

func TestNaiveFullCloseReturnsBeforeReadWorkerCleanup(t *testing.T) {
	r := &naivePostReadCleanupGate{
		readEntered: make(chan struct{}), releaseRead: make(chan struct{}),
		closeEntered: make(chan struct{}), releaseClose: make(chan struct{}), closeDone: make(chan struct{}),
	}
	releaseRead := sync.OnceFunc(func() { close(r.releaseRead) })
	releaseClose := sync.OnceFunc(func() { close(r.releaseClose) })
	defer releaseRead()
	defer releaseClose()
	conn := newBodyConn(r, io.Discard, func() error { return nil }, func(bool) {}, streamAddr("a"), streamAddr("b"), time.Hour)
	halfCloseWait(t, r.readEntered)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	halfCloseWait(t, r.closeEntered)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Error("full Close waited for an in-flight transport response Read")
		releaseRead()
		releaseClose()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read after local Close = %T %v, want net.ErrClosed", err, err)
	}
	if _, err := conn.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write after local Close = %T %v, want net.ErrClosed", err, err)
	}
	if err := conn.CloseWrite(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("CloseWrite after local Close = %T %v, want net.ErrClosed", err, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal("repeated Close", err)
	}
	releaseRead()
	releaseClose()
	halfCloseWait(t, conn.pumpDone)
	halfCloseWait(t, r.closeDone)
	halfCloseWait(t, conn.cleanupDone)
}

type naiveCleanupOwnerConnection struct {
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
}

func (c *naiveCleanupOwnerConnection) open(context.Context, string, http.Header) (net.Conn, bool, error) {
	return nil, false, errors.New("unused cleanup owner open")
}
func (c *naiveCleanupOwnerConnection) alive() bool { return true }
func (c *naiveCleanupOwnerConnection) close() error {
	c.closeOnce.Do(func() {
		c.closeCalls.Add(1)
		close(c.closed)
	})
	return nil
}

func TestNaiveClientCloseJoinsDetachedReadCleanup(t *testing.T) {
	r := &naivePostReadCleanupGate{
		readEntered: make(chan struct{}), releaseRead: make(chan struct{}),
		closeEntered: make(chan struct{}), releaseClose: make(chan struct{}), closeDone: make(chan struct{}),
	}
	owner := &naiveCleanupOwnerConnection{closed: make(chan struct{})}
	releaseCleanup := sync.OnceFunc(func() {
		close(r.releaseRead)
		close(r.releaseClose)
	})
	defer releaseCleanup()
	ctx, cancel := context.WithCancel(context.Background())
	slot := &poolSlot{conn: owner, born: time.Now(), active: 1, streams: map[*pooledStream]bool{}}
	client := &Client{
		config: ClientConfig{MaxConnections: 1, MaxStreams: 1, TunnelTimeout: time.Hour, IdleTimeout: time.Hour},
		ctx:    ctx, cancel: cancel, slots: []*poolSlot{slot}, retired: map[*poolSlot]bool{},
		capacity: make(chan struct{}, 1), lifecycle: make(chan struct{}, 2), closeDone: make(chan struct{}),
	}
	client.capacity <- struct{}{}
	client.lifecycle <- struct{}{}
	body := newBodyConn(r, io.Discard, func() error { return nil }, func(bool) {}, streamAddr("a"), streamAddr("b"), time.Hour)
	stream := &pooledStream{Conn: body, raw: body, client: client, slot: slot}
	slot.streams[stream] = true
	client.watchers.Add(1)
	go func() {
		defer client.watchers.Done()
		<-body.done
		_ = stream.Close()
		body.waitCleanup()
		client.release(slot, stream, false)
	}()

	halfCloseWait(t, r.readEntered)
	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	halfCloseWait(t, r.closeEntered)
	halfCloseResult(t, closed)
	if len(client.capacity) != 0 || len(client.lifecycle) != 1 {
		t.Fatalf("post-Close reservations = capacity %d lifecycle %d, want 0/1", len(client.capacity), len(client.lifecycle))
	}
	select {
	case <-body.cleanupDone:
		t.Fatal("cleanup completed before the owned transport was released")
	default:
	}

	clientClosed := make(chan error, 1)
	go func() { clientClosed <- client.Close() }()
	halfCloseWait(t, owner.closed)
	select {
	case err := <-clientClosed:
		t.Fatalf("Client.Close returned before owned stream cleanup: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-body.cleanupDone:
		t.Fatal("cleanup completed while both transport gates remained blocked")
	default:
	}
	releaseCleanup()
	halfCloseResult(t, clientClosed)
	select {
	case <-body.cleanupDone:
	default:
		t.Fatal("Client.Close returned before cleanupDone")
	}
	client.mu.Lock()
	active := slot.active
	client.mu.Unlock()
	if active != 0 || len(client.capacity) != 0 || len(client.lifecycle) != 0 {
		t.Fatalf("final resources = active %d capacity %d lifecycle %d, want 0/0/0", active, len(client.capacity), len(client.lifecycle))
	}
	if owner.closeCalls.Load() != 1 {
		t.Fatalf("physical close calls = %d, want 1", owner.closeCalls.Load())
	}
	if err := stream.Close(); err != nil {
		t.Fatal("repeated stream Close", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal("repeated client Close", err)
	}
}

// A transport response Close may wait on a connection-wide write lock even
// after stream cancellation has already interrupted its Read. Local full Close
// must return independently; the tracked cleanup owner joins both operations
// after that unrelated carrier lock is released.
type naiveBlockingResponseClose struct {
	readEntered, stopRead, closeEntered, releaseClose chan struct{}
	readOnce, closeOnce                               sync.Once
}

func (r *naiveBlockingResponseClose) Read([]byte) (int, error) {
	r.readOnce.Do(func() { close(r.readEntered) })
	<-r.stopRead
	return 0, net.ErrClosed
}
func (r *naiveBlockingResponseClose) Close() error {
	r.closeOnce.Do(func() { close(r.closeEntered) })
	<-r.releaseClose
	return nil
}

func TestNaiveFullCloseIndependentOfBlockedResponseClose(t *testing.T) {
	r := &naiveBlockingResponseClose{
		readEntered: make(chan struct{}), stopRead: make(chan struct{}),
		closeEntered: make(chan struct{}), releaseClose: make(chan struct{}),
	}
	stopOnce := sync.OnceFunc(func() { close(r.stopRead) })
	releaseOnce := sync.OnceFunc(func() { close(r.releaseClose) })
	defer stopOnce()
	defer releaseOnce()
	conn := newBodyConn(r, io.Discard, func() error { return nil }, func(bool) { stopOnce() }, streamAddr("a"), streamAddr("b"), time.Hour)
	halfCloseWait(t, r.readEntered)
	closed := make(chan error, 1)
	go func() { closed <- conn.Close() }()
	halfCloseWait(t, r.closeEntered)
	returned := false
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
		returned = true
	case <-time.After(time.Second):
		t.Error("full Close inherited a blocked transport response Close")
	}
	releaseOnce()
	if !returned {
		halfCloseResult(t, closed)
	}
	halfCloseWait(t, conn.cleanupDone)
}

func (w *naiveWriteGate) Write(p []byte) (int, error) {
	close(w.entered)
	<-w.release
	return w.Writer.Write(p)
}

// Pause the padding encoder between records of one Write, after the first
// record has really been submitted. The target verifies every byte up to EOF.
func TestNaivePaddedWriteAndCloseWrite(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			payload := halfClosePayload(3<<20 + 97)
			target, received := halfCloseTarget(t, func(c *net.TCPConn) error {
				b, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(b, payload) {
					return fmt.Errorf("upload before EOF: %d/%d bytes, %v", len(b), len(payload), err)
				}
				_, err = c.Write([]byte{1})
				return err
			})
			proxy, tc, _ := startTestServer(t, mode)
			client := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Padding = "enabled" }, nil)
			conn := openNaiveStateContractConn(t, client, target)
			p := conn.(*pooledStream).Conn.(*PaddingConn)
			gate := &naivePaddingReadGate{entered: make(chan struct{}), release: make(chan struct{})}
			p.rng = gate
			unblock := sync.OnceFunc(func() { close(gate.release) })
			defer unblock()
			write, half := make(chan error, 1), make(chan error, 1)
			go func() {
				n, err := conn.Write(payload)
				if err == nil && n != len(payload) {
					err = io.ErrShortWrite
				}
				write <- err
			}()
			halfCloseWait(t, gate.entered)
			started := make(chan struct{})
			go func() { close(started); half <- conn.CloseWrite() }()
			halfCloseWait(t, started)
			unblock()
			halfCloseResult(t, write)
			halfCloseResult(t, half)
			if data, err := io.ReadAll(conn); err != nil || !bytes.Equal(data, []byte{1}) {
				t.Fatalf("response after target EOF = %v, %v", data, err)
			}
			halfCloseResult(t, received)
		})
	}
}

type naivePaddingReadGate struct {
	calls            int
	entered, release chan struct{}
}

func (r *naivePaddingReadGate) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 2 {
		close(r.entered)
		<-r.release
	}
	clear(p)
	return len(p), nil
}
