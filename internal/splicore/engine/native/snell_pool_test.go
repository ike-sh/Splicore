package native

import (
	"bytes"
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/protocol/snell/wire"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnellV4PoolSerialFailureIdleAndShutdown(t *testing.T) {
	k, _ := wire.NewKey(4, "SyntheticReuseTestPSK12345")
	var physical atomic.Int32
	dial := func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		physical.Add(1)
		go func() {
			defer b.Close()
			_ = wire.Serve(b, k, func(c *wire.Tunnel, dst access.Endpoint) error {
				if dst.Port == 1 {
					return wire.ErrFrame
				}
				_, e := io.Copy(c, c)
				return e
			}, func(*wire.Packet) error { return wire.ErrFrame })
		}()
		return a, nil
	}
	p := newSnellPool(dial, k)
	defer p.Close()
	p.idleTimeout = 40 * time.Millisecond
	dst := access.Endpoint{Host: "127.0.0.1", Port: 1234}
	var previous net.Conn
	for i := 0; i < 12; i++ {
		c, e := p.acquire(context.Background(), dst)
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		payload := bytes.Repeat([]byte{byte(i), 0, 255}, 2000+i)
		done := make(chan error, 1)
		go func() {
			_, e := c.Write(payload)
			if e == nil {
				e = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- e
		}()
		got, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatal("cross request integrity", i, e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		_ = c.Close()
		if previous != nil && previous.SetDeadline(time.Now()) == nil {
			t.Fatal("closed borrower changed next deadline")
		}
		previous = c
	}
	if physical.Load() != 1 {
		t.Fatal("not reused", physical.Load())
	}
	// Destination failure retires a previously reusable physical connection.
	failed, e := p.acquire(context.Background(), access.Endpoint{Host: "127.0.0.1", Port: 1})
	if e != nil {
		t.Fatal(e)
	}
	_ = failed.SetDeadline(time.Now().Add(time.Second))
	if _, e = failed.Read(make([]byte, 1)); e == nil {
		t.Fatal("failed destination accepted")
	}
	_ = failed.Close()
	c, e := p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	if physical.Load() != 2 {
		t.Fatal("failure not retired")
	}
	_ = c.Close() // Unfinished logical request must be retired.
	p.mu.Lock()
	remaining := len(p.all)
	p.mu.Unlock()
	if remaining != 0 {
		t.Fatal("unfinished borrower retained")
	}
	// Populate an idle entry then wait for the actual bounded cleanup timer.
	c, e = p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	go func() { _, _ = c.Write([]byte("idle")); _ = c.(interface{ CloseWrite() error }).CloseWrite() }()
	if got, e := io.ReadAll(c); e != nil || string(got) != "idle" {
		t.Fatal(got, e)
	}
	_ = c.Close()
	deadline := time.Now().Add(time.Second)
	for {
		p.mu.Lock()
		empty := len(p.all) == 0
		p.mu.Unlock()
		if empty {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("idle cleanup")
		}
		time.Sleep(time.Millisecond)
	}
	c, e = p.acquire(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); done <- e }()
	_ = p.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("shutdown read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown deadlock")
	}
	_ = c.Close()
	if _, e = p.acquire(context.Background(), dst); e == nil {
		t.Fatal("closed pool reopened")
	}
}
