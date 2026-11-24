package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type naivePoolProbeConnection struct {
	blockAlive                 bool
	aliveEntered, releaseAlive chan struct{}
	aliveOnce                  sync.Once
	closeCalls                 atomic.Int32
}

func (c *naivePoolProbeConnection) open(context.Context, string, http.Header) (net.Conn, bool, error) {
	return nil, false, errors.New("unused pool probe open")
}
func (c *naivePoolProbeConnection) alive() bool {
	if c.blockAlive {
		c.aliveOnce.Do(func() { close(c.aliveEntered) })
		<-c.releaseAlive
	}
	return true
}
func (c *naivePoolProbeConnection) close() error { c.closeCalls.Add(1); return nil }

func TestNaivePoolProbeDoesNotBlockStreamRelease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := &naivePoolProbeConnection{blockAlive: true, aliveEntered: make(chan struct{}), releaseAlive: make(chan struct{})}
	normal := &naivePoolProbeConnection{}
	probeSlot := &poolSlot{conn: probe, born: time.Now(), streams: map[*pooledStream]bool{}}
	normalSlot := &poolSlot{conn: normal, born: time.Now(), active: 1, streams: map[*pooledStream]bool{}}
	client := &Client{
		config: ClientConfig{MaxConnections: 2, MaxStreams: 2, TunnelTimeout: time.Hour, IdleTimeout: time.Hour},
		ctx:    ctx, cancel: cancel, slots: []*poolSlot{probeSlot, normalSlot}, retired: map[*poolSlot]bool{},
		capacity: make(chan struct{}, 2), lifecycle: make(chan struct{}, 4), closeDone: make(chan struct{}),
	}
	client.capacity <- struct{}{}
	client.lifecycle <- struct{}{}
	local, remote := net.Pipe()
	defer remote.Close()
	stream := &pooledStream{Conn: local, raw: local, client: client, slot: normalSlot}
	normalSlot.streams[stream] = true

	acquired := make(chan *poolSlot, 1)
	acquireErr := make(chan error, 1)
	go func() {
		slot, err := client.acquire(t.Context())
		if err != nil {
			acquireErr <- err
			return
		}
		acquired <- slot
	}()
	halfCloseWait(t, probe.aliveEntered)
	releaseProbe := sync.OnceFunc(func() { close(probe.releaseAlive) })
	defer releaseProbe()

	closed := make(chan error, 1)
	go func() { closed <- stream.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Error("stream Close waited behind an unrelated connection liveness probe")
		releaseProbe()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
	}
	if got := len(client.capacity); got != 0 {
		t.Errorf("capacity after stream Close = %d, want 0", got)
	}
	if err := stream.Close(); err != nil {
		t.Fatal("repeated Close", err)
	}
	if got := len(client.capacity); got != 0 {
		t.Errorf("repeated Close changed capacity to %d", got)
	}
	released := make(chan struct{})
	go func() { client.release(normalSlot, stream, false); close(released) }()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Error("stream resource release waited behind an unrelated connection liveness probe")
		releaseProbe()
		<-released
	}
	client.mu.Lock()
	active := normalSlot.active
	client.mu.Unlock()
	if active != 0 || len(client.lifecycle) != 0 {
		t.Errorf("released resources = active %d lifecycle %d, want 0/0", active, len(client.lifecycle))
	}
	if !normal.alive() {
		t.Fatal("unrelated connection became unusable")
	}

	releaseProbe()
	select {
	case slot := <-acquired:
		if slot != probeSlot {
			t.Fatalf("acquired slot = %p, want probe slot %p", slot, probeSlot)
		}
		client.mu.Lock()
		slot.active-- // acquire is exercised directly, so no public capacity token was reserved.
		client.mu.Unlock()
	case err := <-acquireErr:
		t.Fatal(err)
	case <-t.Context().Done():
		t.Fatal("liveness probe did not finish")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if probe.closeCalls.Load() != 1 || normal.closeCalls.Load() != 1 {
		t.Fatalf("physical close calls = probe %d normal %d, want 1 each", probe.closeCalls.Load(), normal.closeCalls.Load())
	}
}

type naiveBlockingPoolCloseConnection struct {
	closeEntered, releaseClose, closeDone chan struct{}
	closeOnce                             sync.Once
	closeCalls                            atomic.Int32
}

func (c *naiveBlockingPoolCloseConnection) open(context.Context, string, http.Header) (net.Conn, bool, error) {
	return nil, false, errors.New("unused blocking pool close open")
}
func (c *naiveBlockingPoolCloseConnection) alive() bool { return true }
func (c *naiveBlockingPoolCloseConnection) close() error {
	c.closeOnce.Do(func() {
		c.closeCalls.Add(1)
		close(c.closeEntered)
		<-c.releaseClose
		close(c.closeDone)
	})
	return nil
}

func TestNaiveClientCloseJoinsRetireTimerOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &naiveBlockingPoolCloseConnection{
		closeEntered: make(chan struct{}), releaseClose: make(chan struct{}), closeDone: make(chan struct{}),
	}
	release := sync.OnceFunc(func() { close(conn.releaseClose) })
	defer release()
	slot := &poolSlot{conn: conn, born: time.Now(), streams: map[*pooledStream]bool{}, idleGeneration: 1}
	client := &Client{
		config: ClientConfig{MaxConnections: 1, MaxStreams: 1, TunnelTimeout: time.Hour},
		ctx:    ctx, cancel: cancel, slots: []*poolSlot{slot}, retired: map[*poolSlot]bool{},
		capacity: make(chan struct{}, 1), lifecycle: make(chan struct{}, 2), closeDone: make(chan struct{}),
	}

	client.expireIdle(slot, 0)
	client.mu.Lock()
	if slot.retired || client.slots[0] != slot {
		client.mu.Unlock()
		t.Fatal("stale idle generation retired the current slot")
	}
	client.scheduleIdleLocked(slot) // zero delay: callback owns removal and physical close.
	client.mu.Unlock()
	halfCloseWait(t, conn.closeEntered)

	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Client.Close returned before timer-owned physical close: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	halfCloseResult(t, closed)
	select {
	case <-conn.closeDone:
	default:
		t.Fatal("Client.Close returned before timer-owned closeDone")
	}
	if conn.closeCalls.Load() != 1 {
		t.Fatalf("timer-owned physical close calls = %d, want 1", conn.closeCalls.Load())
	}
	if err := client.Close(); err != nil {
		t.Fatal("repeated Client.Close", err)
	}
}

func TestNaiveBoundedPoolAndConcurrentUsers(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			for _, limit := range []int{2, 4} {
				var count atomic.Int64
				alpha := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.MaxConnections = limit }, &count)
				beta := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Username = "beta"; c.Password = "beta-pass" }, nil)
				var streams []net.Conn
				for i := 0; i < 8; i++ {
					for _, client := range []*Client{alpha, beta} {
						c, err := client.Open(context.Background(), target)
						if err != nil {
							t.Fatal(err)
						}
						streams = append(streams, c)
					}
				}
				if count.Load() != int64(limit) {
					t.Fatal("connection bound/reuse", count.Load(), limit)
				}
				var wg sync.WaitGroup
				results := make(chan error, len(streams))
				for id, c := range streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer c.Close()
						c.SetDeadline(time.Now().Add(5 * time.Second))
						data := bytes.Repeat([]byte{byte(id)}, 1000+id)
						_, err := c.Write(data)
						if err == nil {
							got := make([]byte, len(data))
							_, err = io.ReadFull(c, got)
							if err == nil && !bytes.Equal(data, got) {
								err = ErrProtocol
							}
						}
						results <- err
					}()
				}
				wg.Wait()
				close(results)
				for err := range results {
					if err != nil {
						t.Fatal(err)
					}
				}
				alpha.Close()
				beta.Close()
			}
		})
	}
}
