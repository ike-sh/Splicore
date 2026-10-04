package clientruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/networkruntime"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
)

type phase15Resources struct{ Goroutines, FDs, Listeners, Sessions, Generations, Leases int }

func phase15Measure(m *Manager) phase15Resources {
	r := phase15Resources{Goroutines: runtime.NumGoroutine(), FDs: -1}
	if files, err := os.ReadDir("/proc/self/fd"); err == nil {
		r.FDs = len(files)
	}
	if m != nil {
		m.mu.Lock()
		r.Listeners = len(m.listeners)
		r.Sessions = len(m.sessions)
		r.Generations = len(m.networkOwners)
		m.mu.Unlock()
		r.Leases = len(m.underlay.Status().Generations)
	}
	return r
}
func phase15Peak(a, b phase15Resources) phase15Resources {
	return phase15Resources{max(a.Goroutines, b.Goroutines), max(a.FDs, b.FDs), max(a.Listeners, b.Listeners), max(a.Sessions, b.Sessions), max(a.Generations, b.Generations), max(a.Leases, b.Leases)}
}
func phase15CheckStable(t *testing.T, start, end phase15Resources) {
	t.Helper()
	// Go's runtime may retain its poller descriptor and a bounded cleanup worker.
	if end.Goroutines > start.Goroutines+2 || start.FDs >= 0 && end.FDs > start.FDs+2 || end.Listeners+end.Sessions+end.Generations+end.Leases != 0 {
		t.Fatalf("resource ownership leaked: start=%+v end=%+v", start, end)
	}
}

func TestPhase15GenerationOwnershipAndSnapshot25x(t *testing.T) {
	start := phase15Measure(nil)
	peak := start
	factories, _ := registry.NewOutbounds()
	for iteration := range 25 {
		m := New()
		state := client.Empty()
		id, _ := identity.NewID()
		state.Network.Route.Rules = []P.RouteRule{{ID: id, Name: "owned", Match: P.RuleMatch{Domains: []string{"owned.test"}}, Action: P.Action{Kind: P.Direct}}}
		p, err := m.Prepare(context.Background(), state, nil, factories)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Activate(); err != nil {
			t.Fatal(err)
		}
		held := m.acquire()
		state.Network.Route.Rules[0].Action.Kind = P.Reject
		p, err = m.Prepare(context.Background(), state, nil, factories)
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Activate(); err != nil {
			t.Fatal(err)
		}
		peak = phase15Peak(peak, phase15Measure(m))
		if held.refs.Load() != 1 || len(m.underlay.Status().Generations) != 2 {
			t.Fatal("old generation retired before final owner", iteration)
		}
		barrier := make(chan struct{})
		var workers sync.WaitGroup
		for range 8 {
			workers.Go(func() {
				<-barrier
				for range 32 {
					current := m.acquire()
					if current == nil {
						t.Error("published generation absent")
						return
					}
					q := networkruntime.Query{Domain: "owned.test", Port: 80, Network: "tcp"}
					if current.network.Matcher.Match(q, P.Action{}, true).Action.Kind != P.Reject || held.network.Matcher.Match(q, P.Action{}, true).Action.Kind != P.Direct {
						t.Error("mixed routing snapshot")
					}
					_ = m.Status(state, nil)
					_ = current.release()
				}
			})
		}
		close(barrier)
		workers.Wait()
		if err = held.release(); err != nil {
			t.Fatal(err)
		}
		if len(m.underlay.Status().Generations) != 1 {
			t.Fatal("retired lease not released")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = m.Close(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		phase15CheckStable(t, start, phase15Measure(m))
	}
	end := phase15Measure(nil)
	phase15CheckStable(t, start, end)
	t.Logf("RESOURCE pure repetitions=25 start=%+v peak=%+v end=%+v temp_files=0 (no file writes)", start, peak, end)
}

func TestPhase15OwnedNetworkLifecycle10x(t *testing.T) {
	start := phase15Measure(nil)
	peak := start
	for iteration := range 10 {
		t.Run(fmt.Sprint(iteration), func(t *testing.T) {
			m, state, factories, udpEcho := udpFixture(t)
			tcpEcho, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var echoWorker sync.WaitGroup
			t.Cleanup(func() { _ = tcpEcho.Close(); echoWorker.Wait() })
			echoWorker.Go(func() {
				c, err := tcpEcho.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				// The fixture uses ordinary copy so Linux's stdlib splice pipe
				// pool does not become part of the Splicore FD measurement.
				_, _ = io.Copy(struct{ io.Writer }{c}, struct{ io.Reader }{c})
			})
			address := net.JoinHostPort(state.LocalInbounds[0].Listen.Host, strconv.Itoa(int(state.LocalInbounds[0].Listen.Port)))
			c, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			target := M.ParseSocksaddr(tcpEcho.Addr().String())
			if _, err = socks.ClientHandshake5(c, socks5.CommandConnect, target, "", ""); err != nil {
				t.Fatal(err)
			}
			pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			control, relay, err := udpControl(state, M.ParseSocksaddr(pc.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			if err = udpRoundtrip(pc, relay, udpEcho.LocalAddr(), []byte("owned UDP")); err != nil {
				t.Fatal(err)
			}
			// Hold TCP and UDP references while publishing a complete replacement.
			state.Revision++
			p, err := m.Prepare(context.Background(), state, nil, factories)
			if err != nil {
				t.Fatal(err)
			}
			if err = p.Activate(); err != nil {
				t.Fatal(err)
			}
			peak = phase15Peak(peak, phase15Measure(m))
			if _, err = c.Write([]byte("half-close integrity")); err != nil {
				t.Fatal(err)
			}
			if err = c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(c)
			if err != nil || string(b) != "half-close integrity" {
				t.Fatal("half-close/EOF", err)
			}
			if err = udpRoundtrip(pc, relay, udpEcho.LocalAddr(), []byte("retired UDP still owned")); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err = m.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if len(m.sessions)+len(m.networkOwners)+len(m.underlay.Status().Generations) != 0 {
				t.Fatal("shutdown retained sessions or generations")
			}
			probe, err := net.Listen("tcp", address)
			if err != nil {
				t.Fatal("listener not released", err)
			}
			probe.Close()
			rebound, err := net.ListenUDP("udp4", relay.UDPAddr())
			if err != nil {
				t.Fatal("UDP relay not released", err)
			}
			rebound.Close()
		})
		phase15CheckStable(t, start, phase15Measure(nil))
	}
	end := phase15Measure(nil)
	phase15CheckStable(t, start, end)
	t.Logf("RESOURCE network repetitions=10 start=%+v peak=%+v end=%+v temp_files=0 (socket-only fixtures)", start, peak, end)
}
