package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/protocol/anytls/wire"
)

func pool(t *testing.T, pc PoolConfig, sc Config) *Client {
	t.Helper()
	var mu sync.Mutex
	var servers []*Session
	var setup sync.WaitGroup
	dial := func(ctx context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		setup.Add(1)
		go func() {
			defer setup.Done()
			if _, err := wire.ReadAuthentication(b); err != nil {
				b.Close()
				return
			}
			s, err := NewServer(b, sc, echo)
			if err != nil {
				return
			}
			mu.Lock()
			servers = append(servers, s)
			mu.Unlock()
		}()
		return a, nil
	}
	c, err := NewClientPool(dial, wire.PasswordKey("test"), pc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.Close()
		setup.Wait()
		mu.Lock()
		defer mu.Unlock()
		for _, s := range servers {
			s.Close()
			s.Wait()
		}
	})
	return c
}
func TestPoolNewestIdleCleanupAndActiveProtection(t *testing.T) {
	pc := PoolConfig{Session: testConfig(t, 2), IdleCheck: 5 * time.Millisecond, IdleTimeout: 25 * time.Millisecond, MinIdle: 1}
	c := pool(t, pc, testConfig(t, 2))
	a, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if a.session == b.session || c.State().LastSequence != 2 {
		t.Fatal("busy session reused by default")
	}
	a.Close()
	b.Close()
	d, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if d.session != b.session {
		t.Fatal("newest idle session not selected")
	}
	time.Sleep(70 * time.Millisecond)
	if d.session.Err() != nil {
		t.Fatal("active session expired")
	}
	d.Close()
	eventually(t, func() bool { return c.State().Sessions == 1 })
	if c.State().LastSequence != 2 {
		t.Fatal("unexpected prewarming")
	}
}
func TestPoolMultiplexLimitsAndDynamicPadding(t *testing.T) {
	custom := policy(t, "stop=3\n0=7-7\n1=80-80\n2=100-100,c,120-120")
	sc := testConfig(t, 2)
	sc.Padding = custom
	c := pool(t, PoolConfig{Session: testConfig(t, 2), MaxSessions: 2, MultiplexStreams: 2}, sc)
	a, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.State().PaddingHash == custom.Hash() })
	if a.session.cfg.Padding.Hash() == custom.Hash() {
		t.Fatal("active scheme mutated")
	}
	b, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if b.session != a.session {
		t.Fatal("active multiplex missing")
	}
	d, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if d.session == a.session || d.session.cfg.Padding.Hash() != custom.Hash() {
		t.Fatal("future scheme not applied")
	}
	e, err := c.Open(context.Background(), []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Open(context.Background(), []byte{0}); !errors.Is(err, ErrLimit) {
		t.Fatal("session bound", err)
	}
	for _, st := range []*Stream{a, b, d, e} {
		if err = exchange(st, []byte("exact padded payload")); err != nil {
			t.Fatal(err)
		}
		st.Close()
	}
}
func TestPoolCloseCancelsPendingDialAndJoins(t *testing.T) {
	entered := make(chan struct{})
	c, err := NewClientPool(func(ctx context.Context) (net.Conn, error) { close(entered); <-ctx.Done(); return nil, ctx.Err() }, wire.PasswordKey("test"), PoolConfig{})
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := c.Open(context.Background(), []byte{0}); finished <- err }()
	<-entered
	c.Close()
	if err := <-finished; err == nil {
		t.Fatal("pending dial survived")
	}
	if c.State().Pending != 0 {
		t.Fatal("pending leak")
	}
	if _, err = c.Open(context.Background(), []byte{0}); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	c.Close()
}
