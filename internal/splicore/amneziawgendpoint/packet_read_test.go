package amneziawgendpoint

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

type packetReadResult struct {
	data []byte
	err  error
}

func packetStartRead(p *routedPacket) <-chan packetReadResult {
	done := make(chan packetReadResult, 1)
	go func() {
		b := make([]byte, 128)
		n, _, err := p.ReadFrom(b)
		done <- packetReadResult{b[:n], err}
	}()
	return done
}

func packetReadEntered(t *testing.T, p *routedPacket, count int) {
	t.Helper()
	synctest.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reads) != count {
		t.Fatalf("registered reads=%d want=%d", len(p.reads), count)
	}
}

func packetReadError(t *testing.T, done <-chan packetReadResult, want error) []byte {
	t.Helper()
	select {
	case result := <-done:
		errors := make(chan error, 1)
		errors <- result.err
		packetError(t, errors, want)
		return result.data
	default:
		t.Fatal("read remains blocked")
		return nil
	}
}

func packetReadPending(t *testing.T, done <-chan packetReadResult) {
	t.Helper()
	select {
	case result := <-done:
		t.Fatalf("read unexpectedly completed: %v", result.err)
	default:
	}
}

func TestPacketReadClose200(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 200 {
			p, d, _, _ := packetFixture(t)
			done := packetStartRead(p)
			packetReadEntered(t, p, 1)
			if err := p.Close(); err != nil {
				t.Fatal(err)
			}
			synctest.Wait()
			packetReadError(t, done, net.ErrClosed)
			packetIdle(t, p, d)
			_ = p.Close()
		}
		t.Log("blocked reads + Close: net.ErrClosed=200/200 timeout=0/200")
	})
}

func TestPacketReadAfterClose100(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		_ = p.Close()
		for range 100 {
			_, _, err := p.ReadFrom(make([]byte, 128))
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		}
		packetIdle(t, p, d)
		if err := p.SetReadDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Fatal("read deadline accepted after Close", err)
		}
	})
}

func TestPacketReadDeadline(t *testing.T) {
	for _, mode := range []string{"preset", "after-start", "already-expired"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				switch mode {
				case "preset":
					_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				case "already-expired":
					_ = p.SetReadDeadline(time.Now().Add(-time.Second))
				}
				done := packetStartRead(p)
				if mode != "already-expired" {
					packetReadEntered(t, p, 1)
					if mode == "after-start" {
						_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					}
					time.Sleep(50 * time.Millisecond)
				}
				synctest.Wait()
				packetReadError(t, done, os.ErrDeadlineExceeded)
				packetIdle(t, p, d)
			})
		})
	}
}

func TestPacketReadDeadlineExtend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		done := packetStartRead(p)
		packetReadEntered(t, p, 1)
		_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		time.Sleep(20 * time.Millisecond)
		_ = p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		packetReadPending(t, done)
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		packetReadError(t, done, os.ErrDeadlineExceeded)
		packetIdle(t, p, d)
	})
}

func TestPacketReadDeadlineClear(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, peer := packetFixture(t)
		done := packetStartRead(p)
		packetReadEntered(t, p, 1)
		_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		time.Sleep(20 * time.Millisecond)
		_ = p.SetReadDeadline(time.Time{})
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		packetReadPending(t, done)
		payload := []byte("read deadline cleared")
		go func() { _, _ = peer.Write(payload) }()
		synctest.Wait()
		if got := packetReadError(t, done, nil); !bytes.Equal(got, payload) {
			t.Fatalf("received=%q", got)
		}
		packetIdle(t, p, d)
	})
}

func TestPacketReadWriteDeadlineIndependence(t *testing.T) {
	for _, mode := range []string{"read-only", "write-only", "both"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, peer := packetFixture(t)
				reading, writing := packetStartRead(p), packetStart(p)
				packetReadEntered(t, p, 1)
				packetEntered(t, d, 1)
				deadline := time.Now().Add(50 * time.Millisecond)
				var err error
				switch mode {
				case "read-only":
					err = p.SetReadDeadline(deadline)
				case "write-only":
					err = p.SetWriteDeadline(deadline)
				case "both":
					err = p.SetDeadline(deadline)
				}
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
				if mode == "write-only" {
					packetReadPending(t, reading)
					go func() { _, _ = peer.Write([]byte("read unaffected")) }()
					synctest.Wait()
					packetReadError(t, reading, nil)
				} else {
					packetReadError(t, reading, os.ErrDeadlineExceeded)
				}
				if mode == "read-only" {
					packetEntered(t, d, 1)
					go func() { _, _ = io.Copy(io.Discard, peer) }()
					close(d.release)
					synctest.Wait()
					packetError(t, writing, nil)
				} else {
					packetError(t, writing, os.ErrDeadlineExceeded)
				}
				packetIdle(t, p, d)
				_ = p.Close()
			})
		})
	}
}

// Delay return after the real read has been interrupted, so the next event
// occurs before routedPacket classifies and completes the registered read.
type heldPacketRead struct {
	net.PacketConn
	returned chan struct{}
	release  chan struct{}
}

func (c *heldPacketRead) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	close(c.returned)
	<-c.release
	return n, addr, err
}

func TestPacketReadWriteCancellationOrdering(t *testing.T) {
	for _, first := range []string{"close", "deadline"} {
		t.Run(first, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				hold := &heldPacketRead{PacketConn: p.PacketConn, returned: make(chan struct{}), release: make(chan struct{})}
				p.PacketConn = hold
				reading, writing := packetStartRead(p), packetStart(p)
				packetReadEntered(t, p, 1)
				packetEntered(t, d, 1)
				_ = p.SetDeadline(time.Now().Add(50 * time.Millisecond))
				want := net.ErrClosed
				if first == "deadline" {
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					want = os.ErrDeadlineExceeded
					_ = p.SetDeadline(time.Time{}) // must retain the expired read's reason
				}
				closed := make(chan struct{})
				go func() { _ = p.Close(); close(closed) }()
				<-hold.returned
				synctest.Wait()
				time.Sleep(100 * time.Millisecond)
				close(hold.release)
				<-closed
				synctest.Wait()
				packetReadError(t, reading, want)
				packetError(t, writing, want)
				packetIdle(t, p, d)
			})
		})
	}
}

type packetDeadlineAudit struct {
	net.PacketConn
	mu         sync.Mutex
	read       time.Time
	write      time.Time
	closeRead  time.Time
	closeWrite time.Time
	closeCalls int
}

func (c *packetDeadlineAudit) SetReadDeadline(t time.Time) error {
	err := c.PacketConn.SetReadDeadline(t)
	c.mu.Lock()
	if err == nil {
		c.read = t
	}
	c.mu.Unlock()
	return err
}

func (c *packetDeadlineAudit) SetWriteDeadline(t time.Time) error {
	err := c.PacketConn.SetWriteDeadline(t)
	c.mu.Lock()
	if err == nil {
		c.write = t
	}
	c.mu.Unlock()
	return err
}

func (c *packetDeadlineAudit) SetDeadline(time.Time) error {
	panic("association I/O must use separate read/write deadline state")
}

func (c *packetDeadlineAudit) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.closeRead, c.closeWrite = c.read, c.write
	c.mu.Unlock()
	return c.PacketConn.Close()
}

func TestPacketCloseUsesSocketLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, pipe, _ := packetFixture(t)
		audit := &packetDeadlineAudit{PacketConn: p.PacketConn}
		p.PacketConn = audit
		deadline := time.Now().Add(time.Hour)
		_ = p.SetDeadline(deadline)
		close(d.release)
		reading, writing := packetStartRead(p), packetStart(p)
		packetReadEntered(t, p, 1)
		if pipe.sends.Load() != 1 {
			t.Fatal("write not blocked in transport")
		}
		_ = p.Close()
		synctest.Wait()
		packetReadError(t, reading, net.ErrClosed)
		packetError(t, writing, net.ErrClosed)
		audit.mu.Lock()
		defer audit.mu.Unlock()
		if audit.closeCalls != 1 || audit.closeRead != deadline || audit.closeWrite != deadline {
			t.Fatalf("Close changed transport deadlines before closing socket: read=%v write=%v calls=%d", audit.closeRead, audit.closeWrite, audit.closeCalls)
		}
		packetIdle(t, p, d)
	})
}

func TestPacketReadCloseDeadlineRaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 100 {
			p, d, _, _ := packetFixture(t)
			reading, writing := packetStartRead(p), packetStart(p)
			packetReadEntered(t, p, 1)
			packetEntered(t, d, 1)
			var wg sync.WaitGroup
			wg.Go(func() { _ = p.Close() })
			wg.Go(func() { _ = p.SetDeadline(time.Now()) })
			wg.Wait()
			synctest.Wait()
			read := <-reading
			write := <-writing
			for _, err := range []error{read.err, write} {
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("simultaneous Close/deadline error: %v", err)
				}
			}
			packetIdle(t, p, d)
		}
	})
}

func TestPacketReadChurn120(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		baseline := runtime.NumGoroutine()
		for cycle := range 120 {
			p, d, _, peer := packetFixture(t)
			if cycle%6 == 2 {
				_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			}
			done := packetStartRead(p)
			packetReadEntered(t, p, 1)
			var want error
			switch cycle % 6 {
			case 0:
				go func() { _, _ = peer.Write([]byte("normal packet")) }()
			case 1:
				_ = p.Close()
				want = net.ErrClosed
			case 2:
				time.Sleep(50 * time.Millisecond)
				want = os.ErrDeadlineExceeded
			case 3:
				_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				time.Sleep(50 * time.Millisecond)
				want = os.ErrDeadlineExceeded
			case 4, 5:
				_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				time.Sleep(10 * time.Millisecond)
				next := time.Time{}
				if cycle%6 == 4 {
					next = time.Now().Add(300 * time.Millisecond)
				}
				_ = p.SetReadDeadline(next)
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				packetReadPending(t, done)
				go func() { _, _ = peer.Write([]byte("updated deadline")) }()
			}
			synctest.Wait()
			packetReadError(t, done, want)
			packetIdle(t, p, d)
			_ = p.Close()
			_ = peer.Close()
			synctest.Wait()
		}
		for retry := 0; runtime.NumGoroutine() > baseline && retry < 1000; retry++ {
			runtime.Gosched()
			synctest.Wait()
		}
		if got := runtime.NumGoroutine(); got > baseline {
			t.Fatalf("workers baseline=%d final=%d", baseline, got)
		}
		t.Log("120 mixed reads: reads=0 writes=0 DNS=0 readTimers=0 writeTimers=0 workers=baseline")
	})
}

func TestPacketConcurrentReads(t *testing.T) {
	for _, mode := range []string{"close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				var readers []<-chan packetReadResult
				for range 16 {
					readers = append(readers, packetStartRead(p))
				}
				packetReadEntered(t, p, 16)
				want := net.ErrClosed
				if mode == "close" {
					_ = p.Close()
				} else {
					_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					time.Sleep(50 * time.Millisecond)
					want = os.ErrDeadlineExceeded
				}
				synctest.Wait()
				for _, done := range readers {
					packetReadError(t, done, want)
				}
				packetIdle(t, p, d)
			})
		})
	}
}

func TestPacketReadDeadlineChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		reading, writing := packetStartRead(p), packetStart(p)
		packetReadEntered(t, p, 1)
		packetEntered(t, d, 1)
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(func() {
				for i := range 150 {
					deadline := time.Time{}
					if i%3 != 0 {
						deadline = time.Now().Add(time.Duration(i+1) * time.Millisecond)
					}
					if err := p.SetReadDeadline(deadline); err != nil {
						t.Error(err)
					}
				}
			})
		}
		wg.Wait()
		_ = p.SetReadDeadline(time.Time{})
		time.Sleep(time.Second)
		synctest.Wait()
		packetReadPending(t, reading)
		packetEntered(t, d, 1)
		_ = p.SetReadDeadline(time.Now())
		synctest.Wait()
		packetReadError(t, reading, os.ErrDeadlineExceeded)
		_ = p.Close()
		synctest.Wait()
		packetError(t, writing, net.ErrClosed)
		packetIdle(t, p, d)
	})
}

func TestPacketIdleDeadlinesOwnNoTransportTimers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		audit := &packetDeadlineAudit{PacketConn: p.PacketConn}
		p.PacketConn = audit
		for range 100 {
			if err := p.SetDeadline(time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
		packetIdle(t, p, d)
		_ = p.Close()
		audit.mu.Lock()
		defer audit.mu.Unlock()
		if !audit.read.IsZero() || !audit.write.IsZero() || audit.closeCalls != 1 {
			t.Fatal("idle association retained transport deadline timers")
		}
	})
}
