//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func TestPhase17TUNLifetime25(t *testing.T)         { phase17TUN(t, false) }
func TestPhase17TUNMixedSoak10Minutes(t *testing.T) { phase17TUN(t, true) }

// The lab runs in disposable mount/network namespaces. Resource observations
// belong to tests; no production sampling or diagnostic worker is added.
func phase17TUN(t *testing.T, soak bool) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	journal := filepath.Join(root, "host-network")
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{native.ShadowsocksOutboundFactory{}}
	for _, c := range cases {
		factories = append(factories, c.factory)
	}
	adapters, err := registry.NewOutbounds(factories...)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, adapters, journal); err != nil {
		t.Fatal(err)
	}
	var proxies, inbounds []identity.ID
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		created := ssCreation(t, s, method, method != "aes-128-gcm")
		c := ssCandidate(t, s, created, 0)
		c.Key = method
		c.Node.Name = method
		_, oid := ssImportedOutbound(t, s, c)
		proxies = append(proxies, oid)
		inbounds = append(inbounds, created.InboundID)
	}
	for _, c := range cases {
		port := freePort(t)
		if c.transport == "quic" {
			port = udpPort(t)
		}
		created := expansionCreation(t, s, c, "127.0.0.1", port)
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
		proxies = append(proxies, expansionProxy(t, s, node, "native"))
		inbounds = append(inbounds, created.InboundID)
	}
	var queries, bootstrapQueries atomic.Int64
	resolver := tunResolver(t, &queries)
	bootstrap := appDNS(t, "udp", &bootstrapQueries)
	dnsID, bootstrapID, groupID := networkID(t), networkID(t), networkID(t)
	config := P.Config{Servers: []P.DNSServer{{ID: bootstrapID, Name: "SS bootstrap", Type: "udp", Endpoint: bootstrap, Detour: P.Action{Kind: P.Direct}}, {ID: dnsID, Name: "SS proxied DNS", Type: "tcp", Endpoint: resolver, Detour: P.Action{Kind: P.Outbound, ID: proxies[0]}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: bootstrapID, Strategy: "ipv4_only", TimeoutSeconds: 5, Cache: P.DNSCachePolicy{Capacity: 32}}}
	config.Groups = []P.PolicyGroup{{ID: groupID, Name: "SS TUN selector", Type: "selector", Members: []P.Action{{Kind: P.Outbound, ID: proxies[0]}}, Selector: &P.SelectorSettings{Selected: P.Action{Kind: P.Outbound, ID: proxies[0]}}}}
	for _, proxy := range proxies[1:] {
		config.Groups[0].Members = append(config.Groups[0].Members, P.Action{Kind: P.Outbound, ID: proxy})
	}
	config.Route.Final = &P.Action{Kind: P.Group, ID: groupID}
	applyNetwork(t, s, config)
	var ports map[string]int
	if e := json.Unmarshal([]byte(os.Getenv("SPLICORE_TUN_PORTS")), &ports); e != nil {
		t.Fatal(e)
	}
	before := tunRouteSnapshot(t)
	tun := client.LocalInbound{Name: "Phase17 mixed TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore17", Addresses: []string{"198.18.16.1/30", "fd13:1234:16::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true, Stack: "gvisor"}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &tun})
	rounds := 0
	work := func() {
		for _, proxy := range proxies {
			config.Groups[0].Selector.Selected = P.Action{Kind: P.Outbound, ID: proxy}
			config.Servers[1].Detour = P.Action{Kind: P.Outbound, ID: proxy}
			applyNetwork(t, s, config)
			for _, family := range []string{"v4", "v6"} {
				host := "198.19.0.1"
				if family == "v6" {
					host = "fd13:5678::1"
				}
				for _, network := range []string{"tcp", "udp"} {
					runTUNApp(t, tunAppRequest{Network: network, Target: net.JoinHostPort(host, strconv.Itoa(ports[family+network])), Size: 2048, Concurrent: 1})
				}
			}
			for _, network := range []string{"tcp", "udp"} {
				runTUNApp(t, tunAppRequest{Network: network, Target: "198.19.0.53:53", DNS: true, Concurrent: 1})
			}
		}
		rounds++
	}
	restartServers := func() {
		for _, id := range inbounds {
			view, e := s.Inbound(ctx, id)
			if e != nil {
				t.Fatal(e)
			}
			if view.Inbound.Protocol.Protocol == "snell" {
				// Snell has no binding mutation API; its flow sockets close with
				// the joined client generation and are checked below.
				continue
			}
			state, e := store.State(ctx)
			if e != nil {
				t.Fatal(e)
			}
			b := view.Bindings[0]
			if _, e = s.SetBinding(ctx, id, application.BindingRequest{BindingID: b.BindingID, Enabled: b.Enabled, ResourceRevision: b.Revision, Revision: state.Revision}); e != nil {
				t.Fatal(e)
			}
		}
	}
	stopped := func() {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		restartServers()
		if _, e := net.InterfaceByName(tun.TUN.Interface); e == nil {
			t.Fatal("retained TUN")
		}
		if tunRouteSnapshot(t) != before {
			t.Fatal("route/rule restoration")
		}
		for _, id := range inbounds {
			v, e := s.Inbound(ctx, id)
			if e != nil || v.Stats.Active != 0 {
				t.Fatal("server session residue", e)
			}
		}
	}
	work()
	stopped()
	runtime.GC()
	start := phase17TUNSample(t, s, journal, inbounds)
	peak := start
	sample := func() phase17TUNResources {
		r := phase17TUNSample(t, s, journal, inbounds)
		peak.Goroutines = max(peak.Goroutines, r.Goroutines)
		peak.FDs = max(peak.FDs, r.FDs)
		peak.RSSKiB = max(peak.RSSKiB, r.RSSKiB)
		peak.EventFDs = max(peak.EventFDs, r.EventFDs)
		peak.Listeners = max(peak.Listeners, r.Listeners)
		peak.Sessions = max(peak.Sessions, r.Sessions)
		peak.TCPActive = max(peak.TCPActive, r.TCPActive)
		peak.UDPActive = max(peak.UDPActive, r.UDPActive)
		peak.TCPTotal = max(peak.TCPTotal, r.TCPTotal)
		peak.UDPTotal = max(peak.UDPTotal, r.UDPTotal)
		peak.Generations = max(peak.Generations, r.Generations)
		peak.Leases = max(peak.Leases, r.Leases)
		return r
	}
	if soak {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		begin := time.Now()
		deadline := time.NewTimer(10 * time.Minute)
		defer deadline.Stop()
		cadence := time.NewTicker(3 * time.Second)
		defer cadence.Stop()
		// A fixed offered workload keeps this sanity soak below the documented
		// authenticated association/replay admission caps. No failed I/O is retried.
	loop:
		for {
			select {
			case <-deadline.C:
				break loop
			case <-cadence.C:
				work()
				r := sample()
				if rounds%10 == 0 {
					t.Logf("soak elapsed=%s rounds=%d resources=%+v", time.Since(begin), rounds, r)
				}
			}
		}
		stopped()
		t.Logf("mixed SS/SS2022/Snell/HY2/TUIC/VLESS/Mieru TUN TCP/UDP IPv4/IPv6 routing/policy/proxied DNS duration=%s rounds=%d errors=0 start=%+v peak=%+v stopped=%+v", time.Since(begin), rounds, start, peak, sample())
	} else {
		for cycle := range 25 {
			clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
			work()
			sample()
			stopped()
			runtime.GC()
			end := sample()
			t.Logf("Phase17 all-protocol TUN lifetime=%d TCP=0 UDP=0 resources=%+v", cycle+1, end)
			if end.FDs != start.FDs || end.Goroutines != start.Goroutines || end.EventFDs != start.EventFDs || end.Listeners != start.Listeners || end.Sessions != 0 || end.Generations != start.Generations || end.Leases != start.Leases || end.HostGenerations != 0 || end.Interfaces != 0 || end.JournalTemporaries != 0 {
				t.Fatalf("stopped resources start=%+v end=%+v", start, end)
			}
		}
		t.Logf("x25 start=%+v peak=%+v end=%+v", start, peak, sample())
	}
	if queries.Load() == 0 || bootstrapQueries.Load() != 0 {
		t.Fatal("DNS detour leak", queries.Load(), bootstrapQueries.Load())
	}
}

type phase17TUNResources struct {
	qfTUNResources
	TCPActive, UDPActive, TCPTotal, UDPTotal int64
}

func phase17TUNSample(t *testing.T, s *application.Service, journal string, inbounds []identity.ID) phase17TUNResources {
	t.Helper()
	r := phase17TUNResources{qfTUNResources: qfTUNSample(t, s, journal)}
	for _, id := range inbounds {
		v, e := s.Inbound(context.Background(), id)
		if e != nil {
			t.Fatal(e)
		}
		r.TCPActive += v.Stats.TCPActive
		r.UDPActive += v.Stats.UDPActive
		r.TCPTotal += v.Stats.TCPSessions
		r.UDPTotal += v.Stats.UDPSessions
	}
	return r
}
