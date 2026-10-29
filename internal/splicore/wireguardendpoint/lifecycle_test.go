//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func closedStatus(t *testing.T, e *Endpoint) {
	t.Helper()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	s := e.Status()
	if s.State != Closed || s.UDPResources != 0 || s.QueuedPackets != 0 || e.device != nil || e.stack != nil {
		t.Fatalf("unjoined endpoint: %+v", s)
	}
	select {
	case <-e.done:
	default:
		t.Fatal("shutdown not joined")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func fdCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

func TestWireGuardLifecycleChurn100(t *testing.T) {
	// Warm up lazy runtime resources before observing growth. Every subsequent
	// cycle also requires exact device/socket/queue ownership to reach zero.
	a, b, _, _ := pair(t, false)
	closedStatus(t, a)
	closedStatus(t, b)
	runtime.GC()
	baseG, baseFD := runtime.NumGoroutine(), fdCount()
	for i := range 100 {
		a, b, _, _ := pair(t, i%2 == 0)
		transferUDP(t, a, "10.34.0.2", 64)
		transferUDP(t, b, "fd34::1", 64)
		if i%10 == 0 {
			transferTCP(t, a, "fd34::2")
		}
		closedStatus(t, a)
		closedStatus(t, b)
		if (i+1)%25 == 0 {
			runtime.GC()
			t.Logf("cycle=%d goroutines=%d fds=%d devices=0 sockets=0 queues=0", i+1, runtime.NumGoroutine(), fdCount())
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseG+12 && time.Now().Before(deadline) {
		runtime.GC()
		runtime.Gosched()
	}
	if g := runtime.NumGoroutine(); g > baseG+12 {
		t.Fatalf("goroutine growth base=%d final=%d", baseG, g)
	}
	if final := fdCount(); baseFD >= 0 && final > baseFD+2 {
		t.Fatalf("fd growth base=%d final=%d", baseFD, final)
	}
}

func TestWireGuardPendingDNSClose(t *testing.T) {
	for _, phase := range []string{"start", "tcp", "udp"} {
		t.Run(phase, func(t *testing.T) {
			private, _ := testKeys(t)
			_, public := testKeys(t)
			entered := make(chan struct{})
			finished := make(chan struct{})
			var once sync.Once
			lookup := func(ctx context.Context, _ string) ([]netip.Addr, error) {
				once.Do(func() { close(entered) })
				<-ctx.Done()
				close(finished)
				return nil, ctx.Err()
			}
			config := E.WireGuard{Tag: "dns", PrivateKey: private, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: public, AllowedIPs: []string{"10.34.0.2/32"}}}}
			if phase == "start" {
				config.Peers[0].Endpoint = "peer.invalid:51820"
			}
			e, err := New(context.Background(), config, Options{Dispatcher: &echoDispatcher{}, Underlay: underlay.New(), LookupHost: lookup, LookupEndpoint: lookup})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = e.Close() })
			if phase != "start" {
				if err = e.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch phase {
				case "start":
					err = e.Start(context.Background())
				case "tcp":
					_, err = e.DialContext(context.Background(), access.Endpoint{Host: "target.invalid", Port: 443})
				case "udp":
					_, err = e.ListenPacket(context.Background(), access.Endpoint{Host: "target.invalid", Port: 53})
				}
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("DNS not entered")
			}
			closedStatus(t, e)
			select {
			case <-finished:
			default:
				t.Fatal("Close did not join DNS")
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled operation succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("pending operation leaked")
			}
		})
	}
}

func TestMemoryTUNConcurrentClose(t *testing.T) {
	bridge := newMemoryTUN(1420)
	device := stackDevice{bridge}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(4)
		go func() {
			defer wg.Done()
			for {
				if _, err := bridge.Write([][]byte{{1, 2, 3}}, 0); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				if _, err := device.Read(make([]byte, 1420)); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				if _, err := device.Write([]byte{1, 2, 3}); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for {
				if _, err := bridge.Read([][]byte{make([]byte, 1420)}, []int{0}, 0); err != nil {
					return
				}
			}
		}()
	}
	_ = bridge.Close()
	wg.Wait()
	bridge.drain()
	for range 100 {
		if _, err := bridge.Write([][]byte{{1}}, 0); !errors.Is(err, net.ErrClosed) {
			t.Fatal("TUN accepted after close")
		}
		if _, err := device.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatal("stack accepted after close")
		}
		if _, err := device.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("stack read after close")
		}
		if _, err := bridge.Read([][]byte{make([]byte, 1)}, []int{0}, 0); !errors.Is(err, net.ErrClosed) {
			t.Fatal("TUN read after close")
		}
	}
}

func TestWireGuardConcurrentFlowsAndClose(t *testing.T) {
	a, b, _, _ := pair(t, false)
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() { transferTCP(t, a, "10.34.0.2"); transferUDP(t, a, "fd34::2", 128) })
	}
	wg.Wait()
	c, err := a.DialContext(context.Background(), access.Endpoint{Host: "10.34.0.2", Port: 12345})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reading := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, c); reading <- err }()
	closedStatus(t, a)
	closedStatus(t, b)
	select {
	case <-reading:
	case <-time.After(time.Second):
		t.Fatal("active flow outlived endpoint")
	}
	if err = a.Start(context.Background()); err == nil {
		t.Fatal("closed endpoint restarted")
	}
}

func TestWireGuardWrongCredentials(t *testing.T) {
	for _, mode := range []string{"wrong-psk", "wrong-peer-key", "unauthorized-peer"} {
		t.Run(mode, func(t *testing.T) {
			ka, pa := testKeys(t)
			kb, pb := testKeys(t)
			_, wrong := testKeys(t)
			da, db := &echoDispatcher{}, &echoDispatcher{}
			ac := E.WireGuard{Tag: "a", PrivateKey: ka, Addresses: []string{"10.34.0.1/32"}, Peers: []E.WireGuardPeer{{PublicKey: pb, AllowedIPs: []string{"10.34.0.2/32"}}}}
			bc := E.WireGuard{Tag: "b", PrivateKey: kb, Addresses: []string{"10.34.0.2/32"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32"}}}}
			switch mode {
			case "wrong-psk":
				ac.Peers[0].PreSharedKey, _ = testKeys(t)
				bc.Peers[0].PreSharedKey, _ = testKeys(t)
			case "wrong-peer-key":
				ac.Peers[0].PublicKey = wrong
			case "unauthorized-peer":
				bc.Peers[0].PublicKey = wrong
			}
			b, err := New(context.Background(), bc, Options{Dispatcher: db, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = b.Close() })
			if err = b.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ac.Peers[0].Endpoint = net.JoinHostPort("127.0.0.1", itoa(b.Status().ListenPort))
			a, err := New(context.Background(), ac, Options{Dispatcher: da, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			if err = a.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			c, err := a.DialContext(ctx, access.Endpoint{Host: "10.34.0.2", Port: 12345})
			if c != nil {
				_ = c.Close()
			}
			if err == nil {
				t.Fatal("wrong credentials accepted")
			}
			db.mu.Lock()
			defer db.mu.Unlock()
			if len(db.identities) != 0 {
				t.Fatal("unauthenticated traffic reached Core")
			}
		})
	}
}

func TestWireGuardRouteAndMTUBounds(t *testing.T) {
	a, _, _, _ := pair(t, false)
	for _, ip := range []string{"10.35.0.1", "fd35::1", "10.34.0.1"} {
		if c, err := a.ListenPacket(context.Background(), access.Endpoint{Host: ip, Port: 1}); err == nil {
			_ = c.Close()
			t.Fatalf("disallowed destination accepted: %s", ip)
		}
	}
	for _, ip := range []string{"10.34.0.2", "fd34::2"} {
		c, err := a.ListenPacket(context.Background(), access.Endpoint{Host: ip, Port: 12346})
		if err != nil {
			t.Fatal(err)
		}
		limit := 1392
		if ip == "fd34::2" {
			limit = 1372
		}
		if _, err = c.WriteTo(make([]byte, limit+1), net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 12346))); err == nil {
			t.Fatal("oversize UDP accepted")
		}
		_ = c.Close()
	}
}
