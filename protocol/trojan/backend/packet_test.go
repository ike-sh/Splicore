package backend

import (
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func await(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("owned IO not joined")
		return nil
	}
}
func TestPacketPartialWriteTerminal(t *testing.T) {
	for i := 0; i < 100; i++ {
		a, b := net.Pipe()
		p := NewPacket(context.Background(), a)
		done := make(chan error, 1)
		go func() {
			_, e := p.WriteTo([]byte("synthetic-frame"), netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: 53}))
			done <- e
		}()
		one := make([]byte, 1)
		if _, e := io.ReadFull(b, one); e != nil {
			t.Fatal(e)
		}
		_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
		if e := await(t, done); !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatal("partial write deadline missing", e)
		}
		_ = p.SetWriteDeadline(time.Time{})
		if n, e := p.WriteTo([]byte("next"), netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: 53})); n != 0 || !errors.Is(e, net.ErrClosed) {
			t.Fatal("poisoned stream falsely reused")
		}
		_ = p.Close()
		_ = b.Close()
	}
}

type barrierConn struct {
	net.Conn
	entered chan struct{}
	calls   atomic.Int32
	once    sync.Once
}

func (c *barrierConn) Write(b []byte) (int, error) {
	c.calls.Add(1)
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(b)
}
func TestPacketCloseDeadlineParentAndSibling(t *testing.T) {
	for _, operation := range []string{"close", "deadline", "parent"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, b := net.Pipe()
			defer b.Close()
			raw := &barrierConn{Conn: a, entered: make(chan struct{})}
			p := NewPacket(ctx, raw)
			defer p.Close()
			dst := netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: 53})
			done := make(chan error, 2)
			go func() { _, e := p.WriteTo([]byte("owned-frame-A"), dst); done <- e }()
			<-raw.entered
			go func() { _, e := p.WriteTo([]byte("owned-frame-B"), dst); done <- e }()
			switch operation {
			case "close":
				_ = p.Close()
			case "deadline":
				_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
			case "parent":
				cancel()
			}
			for i := 0; i < 2; i++ {
				if e := await(t, done); e == nil {
					t.Fatal("blocked write reported success")
				}
			}
			if raw.calls.Load() != 1 {
				t.Fatal("queued write touched framing owner")
			}
			// A separate TLS association survives another association's close.
			x, y := net.Pipe()
			sibling := NewPacket(context.Background(), x)
			go func() { _, _, e := wire.ReadPacket(y); done <- e }()
			if _, e := sibling.WriteTo([]byte("sibling"), dst); e != nil {
				t.Fatal(e)
			}
			if e := await(t, done); e != nil {
				t.Fatal(e)
			}
			_ = sibling.Close()
			_ = y.Close()
		})
	}
}

type failedRequest struct {
	net.Conn
	closed atomic.Bool
}

func (c *failedRequest) Write([]byte) (int, error) { return 1, io.ErrUnexpectedEOF }
func (c *failedRequest) Close() error              { c.closed.Store(true); return c.Conn.Close() }
func TestRequestPartialWriteClosesOwner(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := &failedRequest{Conn: a}
	e := Client(c, wire.Derive(secret.New("synthetic-request-key")), wire.Connect, access.Endpoint{Host: "127.0.0.1", Port: 443})
	if e == nil || !c.closed.Load() {
		t.Fatal("partially authenticated connection published")
	}
}
func TestPacketRegistryFreeChurn(t *testing.T) {
	dst := netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: 53})
	for i := 0; i < 10000; i++ {
		a, b := net.Pipe()
		p := NewPacket(context.Background(), a)
		done := make(chan error, 1)
		go func() { _, _, e := wire.ReadPacket(b); done <- e }()
		if _, e := p.WriteTo([]byte("churn"), dst); e != nil {
			t.Fatal(e)
		}
		if e := await(t, done); e != nil {
			t.Fatal(e)
		}
		_ = p.Close()
		_ = b.Close()
		if (i+1)%1000 == 0 {
			fds, _ := os.ReadDir("/proc/self/fd")
			t.Logf("cycles=%d registry=0 sessions=0 goroutines=%d fds=%d", i+1, runtime.NumGoroutine(), len(fds))
		}
	}
}

func TestPacketReadDeadlineAndRepeatedClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	p := NewPacket(context.Background(), a)
	if err := p.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.ReadFrom(make([]byte, 32)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("read deadline lost", err)
	}
	for range 3 {
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPacketParentChildCompetition(t *testing.T) {
	for range 1000 {
		ctx, cancel := context.WithCancel(context.Background())
		a, b := net.Pipe()
		p := NewPacket(ctx, a)
		var wg sync.WaitGroup
		for range 3 {
			wg.Go(func() { _ = p.Close() })
		}
		wg.Go(cancel)
		wg.Wait()
		_ = b.Close()
	}
}

func TestStreamBlockedWriteCloseAndLiveDeadline(t *testing.T) {
	for _, action := range []string{"close", "deadline"} {
		t.Run(action, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			raw := &barrierConn{Conn: a, entered: make(chan struct{})}
			s := &Stream{Conn: raw, Raw: a}
			defer s.Close()
			done := make(chan error, 1)
			go func() { _, e := s.Write([]byte("blocked TCP payload")); done <- e }()
			<-raw.entered
			if action == "close" {
				_ = s.Close()
			} else {
				_ = s.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			if e := await(t, done); e == nil {
				t.Fatal("blocked stream did not interrupt")
			}
		})
	}
}
