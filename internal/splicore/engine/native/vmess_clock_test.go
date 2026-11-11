package native

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
)

type reviewClockBackend struct{ dials atomic.Int64 }

func (*reviewClockBackend) Capabilities() underlay.Capabilities {
	return underlay.Capabilities{PerSocket: true}
}
func (b *reviewClockBackend) Protect(_ context.Context, s underlay.Scope, _, _ string, _ syscall.RawConn) error {
	if s.Purpose == underlay.ServerTarget {
		b.dials.Add(1)
	}
	return nil
}
func (*reviewClockBackend) Reconcile(context.Context, []underlay.Endpoint) error { return nil }
func (*reviewClockBackend) Verify(context.Context) error                         { return nil }

type reviewClockConn struct {
	net.Conn
	entered, prefix chan struct{}
	first           sync.Once
	read            int
}

func (c *reviewClockConn) Read(b []byte) (int, error) {
	c.first.Do(func() { close(c.entered) })
	n, err := c.Conn.Read(b)
	c.read += n
	if c.read == 8 && c.prefix != nil {
		close(c.prefix)
		c.prefix = nil
	}
	return n, err
}
func reviewClockWait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("clock/read barrier timeout")
	}
}

func TestReviewFix1AuthClockRealTraffic(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		timestamp            int64
		fragment, lateHeader bool
		valid                bool
	}{
		{"past119", 881, false, false, true}, {"past120", 880, false, false, true}, {"past121", 879, false, false, false},
		{"present", 1000, false, false, true}, {"future119", 1119, false, false, true}, {"future120", 1120, false, false, true}, {"future121", 1121, false, false, false},
		{"expired-first-byte", 880, false, true, false}, // clock moves before any AuthID byte
		{"fragmented-expired", 880, true, false, false},
		{"full-auth-early-header-late", 880, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := &reviewClockBackend{}
			factory := underlay.NewWithBackend(probe)
			ctx := underlay.WithFactory(context.Background(), factory)
			lease, err := factory.Begin(ctx, true)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			in := vmessIntent(t, false)
			var current atomic.Int64
			current.Store(1000)
			sampled := make(chan struct{})
			var once sync.Once
			compiler := NewVMessCompiler()
			compiler.now = func() time.Time { v := current.Load(); once.Do(func() { close(sampled) }); return time.Unix(v, 0) }
			prepared, err := compiler.Compile(ctx, in)
			if err != nil {
				t.Fatal(err)
			}
			h := prepared.(*vmessHandle)
			h.Activate()
			defer h.Close(ctx)
			var targetBytes, targetAccepts atomic.Int64
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			go func() {
				c, e := target.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				targetAccepts.Add(1)
				b := make([]byte, 9)
				n, e := io.ReadFull(c, b)
				targetBytes.Add(int64(n))
				if e == nil {
					_, _ = c.Write(b)
				}
			}()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			entered, prefix := make(chan struct{}), make(chan struct{})
			h.wg.Add(1)
			go h.serve(&reviewClockConn{Conn: server, entered: entered, prefix: prefix})
			_ = client.SetDeadline(time.Now().Add(2 * time.Second))
			reviewClockWait(t, entered) // old code has already sampled; new code is blocked in AuthID Read
			req, err := wire.NewRequest(netaddrEndpoint(target.Addr()), wire.TCP, wire.None, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			key := module.CommandKey(in.Credentials[0].Payload.(access.UUIDPayload))
			header, err := wire.EncodeRequest(key, req, time.Unix(tc.timestamp, 0), nil)
			if err != nil {
				t.Fatal(err)
			}
			cut := 0
			if tc.fragment {
				_, err = client.Write(header[:8])
				if err != nil {
					t.Fatal(err)
				}
				reviewClockWait(t, prefix)
				cut = 8
				current.Store(1001)
			}
			if tc.name == "expired-first-byte" {
				current.Store(1001)
			}
			if tc.lateHeader && tc.valid {
				_, err = client.Write(header[:16])
				if err != nil {
					t.Fatal(err)
				}
				reviewClockWait(t, sampled)
				cut = 16
				current.Store(1001)
			}
			_, _ = client.Write(append(header[cut:], []byte("late-auth")...))
			err = wire.ReadResponse(client, req)
			if tc.valid {
				if err != nil {
					t.Fatal("legitimate authentication rejected", err)
				}
				b := make([]byte, 9)
				if _, err = io.ReadFull(client, b); err != nil || string(b) != "late-auth" {
					t.Fatal("real reply", err)
				}
			} else if err == nil {
				t.Fatal("invalid authentication returned response")
			}
			client.Close()
			if err = h.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if !tc.valid && (probe.dials.Load() != 0 || targetAccepts.Load() != 0 || targetBytes.Load() != 0) {
				t.Fatal("expired/invalid auth reached target", probe.dials.Load(), targetBytes.Load())
			}
			if tc.valid && (probe.dials.Load() != 1 || targetBytes.Load() != 9) {
				t.Fatal("target instrumentation positive control", probe.dials.Load(), targetBytes.Load())
			}
			t.Logf("valid=%v target_dials=%d target_bytes=%d unexpected_accepts=0", tc.valid, probe.dials.Load(), targetBytes.Load())
		})
	}
}

func TestReviewFix1AuthClockCloseRace(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	compiler := NewVMessCompiler()
	var now atomic.Int64
	now.Store(1000)
	compiler.now = func() time.Time { return time.Unix(now.Load(), 0) }
	p, err := compiler.Compile(ctx, vmessIntent(t, false))
	if err != nil {
		t.Fatal(err)
	}
	h := p.(*vmessHandle)
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := net.Dial("tcp", h.listener.Addr().String())
			if e == nil {
				defer c.Close()
				_, _ = c.Write(make([]byte, 8))
				now.Add(1)
				_, _ = c.Write(make([]byte, 8))
			}
		}()
	}
	if err = h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
