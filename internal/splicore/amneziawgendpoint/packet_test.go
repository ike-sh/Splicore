package amneziawgendpoint

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
)

type packetAddress string

func (a packetAddress) Network() string { return "udp" }
func (a packetAddress) String() string  { return string(a) }

// net.Pipe provides real blocking send and dynamic deadlines without network I/O.
type packetPipe struct {
	net.Conn
	sends atomic.Int64
}

func (p *packetPipe) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.sends.Add(1)
	return p.Write(b)
}

func (p *packetPipe) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.Read(b)
	return n, p.RemoteAddr(), err
}

type packetDNS struct {
	calls   atomic.Int64
	active  atomic.Int64
	cancel  atomic.Int64
	release chan struct{}
	err     error
}

func (d *packetDNS) lookup(ctx context.Context, _ string) ([]netip.Addr, error) {
	d.calls.Add(1)
	d.active.Add(1)
	defer d.active.Add(-1)
	select {
	case <-ctx.Done():
		d.cancel.Add(1)
		return nil, ctx.Err()
	case <-d.release:
		return []netip.Addr{netip.MustParseAddr("10.34.0.2")}, d.err
	}
}

func packetFixture(t *testing.T) (*routedPacket, *packetDNS, *packetPipe, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dns := &packetDNS{release: make(chan struct{})}
	e := &Endpoint{ctx: ctx, cancel: cancel, pending: clientio.New(), config: E.AmneziaWG{Protocol: "amneziawg", Version: "3.1", MTU: 1420}, options: Options{LookupHost: dns.lookup}, addresses: []netip.Addr{netip.MustParseAddr("10.34.0.1")}, routes: []route{{netip.MustParsePrefix("10.34.0.2/32"), "peer"}}}
	c, peer := net.Pipe()
	pipe := &packetPipe{Conn: c}
	p, err := newRoutedPacket(pipe, e, e.addresses[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); e.pending.Close(); _ = peer.Close() })
	return p, dns, pipe, peer
}

func packetStart(p *routedPacket) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := p.WriteTo([]byte("payload"), packetAddress("target.invalid:53"))
		done <- err
	}()
	return done
}

func packetError(t *testing.T, done <-chan error, want error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("error=%v, want errors.Is(_, %v)", err, want)
		}
		if errors.Is(want, os.ErrDeadlineExceeded) {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("deadline error lacks net.Error.Timeout: %v", err)
			}
		}
		if errors.Is(want, net.ErrClosed) {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				t.Fatalf("Close misclassified as timeout: %v", err)
			}
		}
	default:
		t.Fatal("write still blocked")
	}
}

func packetIdle(t *testing.T, p *routedPacket, d *packetDNS) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if d.active.Load() != 0 || len(p.writes) != 0 || p.timer != nil || len(p.reads) != 0 || p.readTimer != nil || p.sends != 0 {
		t.Fatalf("resources: DNS=%d writes=%d sends=%d writeTimer=%v reads=%d readTimer=%v", d.active.Load(), len(p.writes), p.sends, p.timer, len(p.reads), p.readTimer)
	}
}

func packetEntered(t *testing.T, d *packetDNS, n int64) {
	t.Helper()
	synctest.Wait()
	if d.active.Load() != n {
		t.Fatalf("blocked DNS=%d want=%d", d.active.Load(), n)
	}
}

func TestPacketCloseCancelsDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		done := packetStart(p)
		packetEntered(t, d, 1)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		packetError(t, done, net.ErrClosed)
		packetIdle(t, p, d)
		if d.cancel.Load() != 1 {
			t.Fatal("resolver context not canceled")
		}
		_ = p.Close()
	})
}

func TestPacketPresetDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		done := packetStart(p)
		packetEntered(t, d, 1)
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		packetError(t, done, os.ErrDeadlineExceeded)
		packetIdle(t, p, d)
		if d.cancel.Load() != 1 {
			t.Fatal("resolver context not canceled")
		}
	})
}

func TestPacketDeadlineAfterStart(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(map[bool]string{false: "write", true: "read-and-write"}[both], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				done := packetStart(p)
				packetEntered(t, d, 1)
				set := p.SetWriteDeadline
				if both {
					set = p.SetDeadline
				}
				if err := set(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				time.Sleep(50 * time.Millisecond)
				synctest.Wait()
				packetError(t, done, os.ErrDeadlineExceeded)
				packetIdle(t, p, d)
			})
		})
	}
}

func TestPacketDeadlineExtend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, _ := packetFixture(t)
		done := packetStart(p)
		packetEntered(t, d, 1)
		_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		time.Sleep(20 * time.Millisecond)
		_ = p.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		time.Sleep(50 * time.Millisecond)
		packetEntered(t, d, 1) // now beyond A; B is still pending
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		packetError(t, done, os.ErrDeadlineExceeded)
		packetIdle(t, p, d)
	})
}

func TestPacketDeadlineClear(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, _, peer := packetFixture(t)
		done := packetStart(p)
		packetEntered(t, d, 1)
		_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		time.Sleep(20 * time.Millisecond)
		_ = p.SetWriteDeadline(time.Time{})
		time.Sleep(100 * time.Millisecond)
		packetEntered(t, d, 1)
		go func() { _, _ = io.Copy(io.Discard, peer) }()
		close(d.release)
		synctest.Wait()
		packetError(t, done, nil)
		packetIdle(t, p, d)
		_ = p.Close()
	})
}

func TestPacketWriteAfterClose50(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, pipe, _ := packetFixture(t)
		_ = p.Close()
		for range 50 {
			_, err := p.WriteTo([]byte("x"), packetAddress("closed.invalid:53"))
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		}
		if d.calls.Load() != 0 || pipe.sends.Load() != 0 {
			t.Fatal("closed write initiated DNS or send work")
		}
		if err := p.SetWriteDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
			t.Fatal("deadline accepted after Close", err)
		}
		packetIdle(t, p, d)
	})
}

func TestPacketExpiredDeadlineNoDNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, pipe, _ := packetFixture(t)
		_ = p.SetWriteDeadline(time.Now().Add(-time.Second))
		done := packetStart(p)
		synctest.Wait()
		packetError(t, done, os.ErrDeadlineExceeded)
		if d.calls.Load() != 0 || pipe.sends.Load() != 0 {
			t.Fatal("expired write initiated DNS or send work")
		}
		packetIdle(t, p, d)
	})
}

func TestPacketConcurrentWrites(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "endpoint"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				var writes []<-chan error
				for range 16 {
					writes = append(writes, packetStart(p))
				}
				packetEntered(t, d, 16)
				want := net.ErrClosed
				switch mode {
				case "close":
					_ = p.Close()
				case "deadline":
					_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
					time.Sleep(50 * time.Millisecond)
					want = os.ErrDeadlineExceeded
				case "endpoint":
					p.endpoint.cancel()
					p.endpoint.pending.Close()
				}
				synctest.Wait()
				for _, done := range writes {
					packetError(t, done, want)
				}
				if d.cancel.Load() != 16 {
					t.Fatal("resolver contexts not all canceled")
				}
				packetIdle(t, p, d)
			})
		})
	}
}

func TestPacketCancellationOrdering(t *testing.T) {
	for _, first := range []string{"close", "deadline"} {
		t.Run(first, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, _, _ := packetFixture(t)
				// Hold the resolver after observing cancellation, so the second
				// event is guaranteed to precede WriteTo's error classification.
				release := make(chan struct{})
				p.endpoint.options.LookupHost = func(ctx context.Context, host string) ([]netip.Addr, error) {
					_, err := d.lookup(ctx, host)
					<-release
					return nil, err
				}
				done := packetStart(p)
				packetEntered(t, d, 1)
				_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
				closed := make(chan struct{})
				want := net.ErrClosed
				if first == "deadline" {
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
					want = os.ErrDeadlineExceeded
				}
				go func() { _ = p.Close(); close(closed) }()
				synctest.Wait()
				time.Sleep(100 * time.Millisecond)
				close(release)
				synctest.Wait()
				packetError(t, done, want)
				<-closed
				packetIdle(t, p, d)
			})
		})
	}
}

func TestPacketDNSErrorPropagation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, d, pipe, _ := packetFixture(t)
		want := &net.DNSError{Err: "controlled DNS failure", Name: "target.invalid"}
		d.err = want
		close(d.release)
		done := packetStart(p)
		synctest.Wait()
		packetError(t, done, want)
		if pipe.sends.Load() != 0 {
			t.Fatal("DNS error still sent packet")
		}
		packetIdle(t, p, d)
	})
}

func TestPacketSendLifecycle(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "extend", "clear", "endpoint"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p, d, pipe, peer := packetFixture(t)
				close(d.release)
				done := packetStart(p)
				synctest.Wait()
				if pipe.sends.Load() != 1 {
					t.Fatal("send not entered")
				}
				want := net.ErrClosed
				switch mode {
				case "close":
					_ = p.Close()
				case "endpoint":
					p.endpoint.cancel()
					p.endpoint.pending.Close()
				default:
					_ = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
					if mode != "deadline" {
						time.Sleep(20 * time.Millisecond)
						next := time.Time{}
						if mode == "extend" {
							next = time.Now().Add(time.Second)
						}
						_ = p.SetWriteDeadline(next)
					}
					time.Sleep(100 * time.Millisecond)
					want = os.ErrDeadlineExceeded
					if mode != "deadline" {
						select {
						case err := <-done:
							t.Fatalf("old send deadline fired: %v", err)
						default:
						}
						go func() { _, _ = io.Copy(io.Discard, peer) }()
						want = nil
					}
				}
				synctest.Wait()
				packetError(t, done, want)
				packetIdle(t, p, d)
				_ = p.Close()
			})
		})
	}
}

func TestPacketDeadlineChurn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for cycle := range 20 {
			p, d, _, _ := packetFixture(t)
			var writes []<-chan error
			for range 8 {
				writes = append(writes, packetStart(p))
			}
			packetEntered(t, d, 8)
			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					for i := range 150 {
						deadline := time.Time{}
						if i%3 != 0 {
							deadline = time.Now().Add(time.Duration(i+1) * time.Millisecond)
						}
						if err := p.SetWriteDeadline(deadline); err != nil {
							t.Error(err)
						}
					}
				})
			}
			wg.Wait()
			_ = p.SetWriteDeadline(time.Time{})
			time.Sleep(time.Second) // every stale timer would have fired
			packetEntered(t, d, 8)
			want := net.ErrClosed
			if cycle%2 == 0 {
				_ = p.SetWriteDeadline(time.Now())
				want = os.ErrDeadlineExceeded
			} else {
				_ = p.Close()
			}
			synctest.Wait()
			for _, done := range writes {
				packetError(t, done, want)
			}
			packetIdle(t, p, d)
			_ = p.Close()
		}
		t.Log("20 cycles x 600 concurrent deadline changes: active DNS=0 writes=0 timers=0")
	})
}

func TestPacketResolverCompletionRaces(t *testing.T) {
	for _, event := range []string{"close", "deadline"} {
		t.Run(event, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				for range 50 {
					p, d, _, peer := packetFixture(t)
					done := packetStart(p)
					packetEntered(t, d, 1)
					go func() { _, _ = io.Copy(io.Discard, peer) }()
					var wg sync.WaitGroup
					wg.Go(func() { close(d.release) })
					wg.Go(func() {
						if event == "close" {
							_ = p.Close()
						} else {
							_ = p.SetWriteDeadline(time.Now())
						}
					})
					wg.Wait()
					synctest.Wait()
					err := <-done
					want := net.ErrClosed
					if event == "deadline" {
						want = os.ErrDeadlineExceeded
					}
					if err != nil && !errors.Is(err, want) {
						t.Fatalf("completion race error=%v want nil or %v", err, want)
					}
					packetIdle(t, p, d)
					_ = p.Close()
				}
			})
		})
	}
}

func TestPacketRegistrationCloseRaces(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 50 {
			p, d, _, _ := packetFixture(t)
			var writes []<-chan error
			for range 16 {
				writes = append(writes, packetStart(p))
			}
			_ = p.Close()
			synctest.Wait()
			for _, done := range writes {
				packetError(t, done, net.ErrClosed)
			}
			packetIdle(t, p, d)
		}
	})
}
