package native

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSnellV4PoolPeerCloseAndBound(t *testing.T) {
	k, _ := wire.NewKey(4, "SyntheticPoolLifecyclePSK1234")
	var workers sync.WaitGroup
	var peers []net.Conn
	dial := func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		peers = append(peers, b)
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer b.Close()
			_ = wire.Serve(b, k, func(t *wire.Tunnel, _ access.Endpoint) error { _, e := io.Copy(t, t); return e }, func(*wire.Packet) error { return wire.ErrFrame })
		}()
		return a, nil
	}
	p := newSnellPool(dial, k)
	defer func() { _ = p.Close(); workers.Wait() }()
	dst := access.Endpoint{Host: "localhost", Port: 1234}
	transfer := func(c net.Conn) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go func() {
			_, e := c.Write([]byte("peer"))
			if e == nil {
				e = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- e
		}()
		got, e := io.ReadAll(c)
		if e != nil || string(got) != "peer" {
			t.Fatal(string(got), e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		_ = c.Close()
	}
	c, e := p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	transfer(c)
	_ = peers[0].Close()
	c, e = p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("closed peer accepted")
	}
	_ = c.Close()
	c, e = p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	transfer(c)
	active := make([]net.Conn, 0, snellMaxSessions)
	for i := 0; i < snellMaxSessions; i++ {
		c, e := p.acquire(context.Background(), dst)
		if e != nil {
			t.Fatal(i, e)
		}
		active = append(active, c)
	}
	if _, e := p.acquire(context.Background(), dst); e == nil {
		t.Fatal("unbounded pool")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := p.acquire(ctx, dst); e != context.Canceled {
		t.Fatal("cancellation", e)
	}
	for _, c := range active {
		_ = c.Close()
	}
	var idle []net.Conn
	for i := 0; i < snellMaxIdle+2; i++ {
		c, e := p.acquire(context.Background(), dst)
		if e != nil {
			t.Fatal(e)
		}
		idle = append(idle, c)
	}
	for _, c := range idle {
		transfer(c)
	}
	p.mu.Lock()
	size := len(p.idle)
	p.mu.Unlock()
	if size != snellMaxIdle {
		t.Fatal("idle bound", size)
	}
	_ = p.Close()
	p.mu.Lock()
	size = len(p.all)
	p.mu.Unlock()
	if size != 0 {
		t.Fatal("shutdown retention")
	}
}
