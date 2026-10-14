package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/naive/backend"
)

// Join target fixture workers before sampling ownership. A generic reader
// keeps the echo fixture from retaining Linux splice pipes in Go's cache.
func naiveLifecycleTarget(t *testing.T) (net.Listener, <-chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{}, 20)
	var workers sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[conn] = true
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, _ = io.Copy(conn, struct{ io.Reader }{conn})
				_ = conn.Close()
				mu.Lock()
				delete(active, conn)
				mu.Unlock()
				finished <- struct{}{}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-accepted
		mu.Lock()
		for conn := range active {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return l, finished
}

func TestNaiveNativeManagedTCPAttributionAndOwnedLifecycle(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !backend.H3Enabled() {
				t.Skip("with_quic required")
			}
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			listener, targetFinished := naiveLifecycleTarget(t)
			target := netaddrEndpoint(listener.Addr())
			runtime.GC()
			runtime.GC()
			before := runtime.NumGoroutine()
			fdBefore, _ := os.ReadDir("/proc/self/fd")
			for cycle := 0; cycle < 10; cycle++ {
				carrier := "tcp"
				if mode == "quic" {
					carrier = "udp"
				}
				in := testfixture.MieruIntent(t, carrier)
				s := testkit.TLS(t)
				in.Inbound.Protocol = module.Key()
				in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{Mode: mode, TLS: s})
				p, err := (NaiveCompiler{}).Compile(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				h := p.(*naiveHandle)
				if err := h.Start(ctx); err != nil {
					h.Close(ctx)
					t.Fatal(err)
				}
				h.Activate()
				for user := range 2 {
					n, c := trojanNode(t, in, s, user)
					n.Protocol = module.Key()
					n.Transport.Kind = module.Carrier(mode)
					n.Options.Data, _ = json.Marshal(module.ClientOptions{Mode: mode})
					d, err := (NaiveOutboundFactory{}).Build(ctx, n, c)
					if err != nil {
						h.Close(ctx)
						t.Fatal(err)
					}
					if d.(*naiveDialer).SupportsNetwork("udp") {
						t.Fatal("UDP falsely claimed")
					}
					if pc, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, target); err == nil {
						pc.Close()
						t.Fatal("UDP accepted")
					}
					anytlsTCP(t, d, target)
					if err := d.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-targetFinished:
					case <-time.After(5 * time.Second):
						t.Fatal("target fixture worker did not join")
					}
					if h.BindingStats(in.Bindings[user].ID).Upload == 0 || h.BindingStats(in.Bindings[user].ID).Download == 0 {
						t.Fatal("missing binding accounting")
					}
				}
				closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err = h.Close(closeCtx)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if h.Stats().Active != 0 {
					t.Fatal("server session leaked")
				}
				// The same socket must be reusable immediately after joined shutdown.
				addr := net.JoinHostPort(in.Inbound.Listeners[0].Endpoint.Host, portString(in.Inbound.Listeners[0].Endpoint.Port))
				if mode == "quic" {
					p, err := net.ListenPacket("udp", addr)
					if err != nil {
						t.Fatal("UDP socket retained", err)
					}
					p.Close()
				} else {
					l, err := net.Listen("tcp", addr)
					if err != nil {
						t.Fatal("TCP socket retained", err)
					}
					l.Close()
				}
			}
			runtime.GC()
			runtime.GC()
			until := time.Now().Add(time.Second)
			fdAfter, _ := os.ReadDir("/proc/self/fd")
			for (runtime.NumGoroutine() > before+2 || len(fdAfter) > len(fdBefore)) && time.Now().Before(until) {
				time.Sleep(time.Millisecond)
				fdAfter, _ = os.ReadDir("/proc/self/fd")
			}
			if runtime.NumGoroutine() > before+2 || len(fdAfter) > len(fdBefore) {
				t.Fatalf("owned lifecycle grew: goroutines %d -> %d; fd %d -> %d", before, runtime.NumGoroutine(), len(fdBefore), len(fdAfter))
			}
			t.Logf("10 joined cycles; goroutines %d -> %d; fd %d -> %d", before, runtime.NumGoroutine(), len(fdBefore), len(fdAfter))
		})
	}
}
