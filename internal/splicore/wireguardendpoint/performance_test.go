//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/testkit/netbench"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

type performanceDispatcher struct{}

func (performanceDispatcher) TCP(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
	_ = c.SetDeadline(time.Now().Add(120 * time.Second))
	_ = netbench.ServeTCP(c)
}
func (performanceDispatcher) UDP(_ context.Context, c net.Conn, _, _ netip.AddrPort) {
	b := make([]byte, 65535)
	for {
		n, e := c.Read(b)
		if e != nil {
			return
		}
		if _, e = c.Write(b[:n]); e != nil {
			return
		}
	}
}

func TestP2WireGuardBaseline(t *testing.T) {
	path := os.Getenv("SPLICORE_PERF_CONFIG")
	if path == "" {
		t.Skip("NOT EXECUTED: use scripts/performance/run.py --suite wireguard")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var scenarios []netbench.Scenario
	if err = json.Unmarshal(b, &scenarios); err != nil || len(scenarios) == 0 {
		t.Fatal("invalid scenarios", err)
	}
	r, err := netbench.NewRecorder(os.Getenv("SPLICORE_PERF_RAW"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if e := r.Close(); e != nil {
			t.Error(e)
		}
	}()
	for _, s := range scenarios {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		if s.Protocol != "wireguard" {
			t.Fatal("userspace WireGuard scenario required")
		}
		stop := netbench.SampleResources(r, s.Name)
		passed := t.Run(s.Name, func(t *testing.T) {
			r.Record(map[string]any{"kind": "scenario", "config": s})
			ka, pa := testKeys(t)
			kb, pb := testKeys(t)
			bc := E.WireGuard{Backend: E.Userspace, Tag: "perf-peer", PrivateKey: kb, Addresses: []string{"10.34.0.2/32", "fd34::2/128"}, Peers: []E.WireGuardPeer{{PublicKey: pa, AllowedIPs: []string{"10.34.0.1/32", "fd34::1/128"}}}}
			peer, err := New(context.Background(), bc, Options{Dispatcher: performanceDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := peer.Close(); e != nil {
					t.Error(e)
				}
			})
			if err = peer.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			ac := E.WireGuard{Backend: E.Userspace, Tag: "perf-client", PrivateKey: ka, Addresses: []string{"10.34.0.1/32", "fd34::1/128"}, Peers: []E.WireGuardPeer{{PublicKey: pb, Endpoint: net.JoinHostPort(s.Ingress, itoa(peer.Status().ListenPort)), AllowedIPs: []string{"10.34.0.2/32", "fd34::2/128"}}}}
			endpoint, err := New(context.Background(), ac, Options{Dispatcher: performanceDispatcher{}, Underlay: underlay.New()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if e := endpoint.Close(); e != nil {
					t.Error(e)
				}
			})
			if err = endpoint.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			host := "10.34.0.2"
			if s.Egress == "::1" {
				host = "fd34::2"
			}
			dst := access.Endpoint{Host: host, Port: 12345}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.TimeoutSeconds)*time.Second)
			defer cancel()
			dial := func(ctx context.Context) (net.Conn, error) { return endpoint.DialContext(ctx, dst) }
			packet := func(ctx context.Context) (net.PacketConn, error) { return endpoint.ListenPacket(ctx, dst) }
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, s.Connections*2)
			for i := 0; i < s.Connections; i++ {
				if s.Network != "udp" {
					wg.Add(1)
					go func(index int) { defer wg.Done(); <-start; errs <- netbench.RunTCP(ctx, r, s, index, dial) }(i)
				}
				if s.Network != "tcp" {
					wg.Add(1)
					go func(index int) {
						defer wg.Done()
						<-start
						errs <- netbench.RunUDP(ctx, r, s, index, packet, &net.UDPAddr{IP: net.ParseIP(host), Port: 12345})
					}(i)
				}
			}
			stamp := time.Now()
			close(start)
			wg.Wait()
			close(errs)
			r.Record(map[string]any{"kind": "group", "scenario": s.Name, "elapsed_ns": time.Since(stamp).Nanoseconds()})
			for e := range errs {
				if e != nil {
					t.Error(e)
				}
			}
		})
		r.Record(map[string]any{"kind": "outcome", "scenario": s.Name, "passed": passed})
		stop()
	}
}
