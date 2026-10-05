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

	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/registry"
)

// Each measured lifetime owns a real kernel TUN, NIC/stack/workers, TCP, UDP,
// DNS, route and policy handoff, generations and journal restoration.
func TestNativeTUNCompleteLifetime25x(t *testing.T) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	journal := filepath.Join(root, "host-network")
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	c := expansionCases(t)[0]
	adapters, err := registry.NewOutbounds(c.factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableClientRuntime(ctx, adapters, journal); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	created := expansionCreation(t, s, c, "127.0.0.1", port)
	node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
	proxy := expansionProxy(t, s, node, "native")
	var queries, bootstrapQueries atomic.Int64
	resolver := tunResolver(t, &queries)
	bootstrap := appDNS(t, "udp", &bootstrapQueries)
	dnsID, bootstrapID, groupID := networkID(t), networkID(t), networkID(t)
	config := P.Config{Servers: []P.DNSServer{{ID: bootstrapID, Name: "native bootstrap", Type: "udp", Endpoint: bootstrap, Detour: P.Action{Kind: P.Direct}}, {ID: dnsID, Name: "native DNS", Type: "tcp", Endpoint: resolver, Detour: P.Action{Kind: P.Outbound, ID: proxy}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: bootstrapID, Strategy: "ipv4_only", TimeoutSeconds: 5, Cache: P.DNSCachePolicy{Capacity: 32}}}
	config.Groups = []P.PolicyGroup{{ID: groupID, Name: "native selector", Type: "selector", Members: []P.Action{{Kind: P.Direct}, {Kind: P.Outbound, ID: proxy}}, Selector: &P.SelectorSettings{Selected: P.Action{Kind: P.Outbound, ID: proxy}}}}
	config.Route.Final = &P.Action{Kind: P.Group, ID: groupID}
	applyNetwork(t, s, config)
	var ports map[string]int
	if err := json.Unmarshal([]byte(os.Getenv("SPLICORE_TUN_PORTS")), &ports); err != nil {
		t.Fatal(err)
	}
	before := tunRouteSnapshot(t)
	inbound := client.LocalInbound{Name: "Native lifetime TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicorentun", Addresses: []string{"198.18.14.1/30", "fd13:1234:14::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &inbound})
	workload := func() {
		for _, family := range []string{"v4", "v6"} {
			host := "198.19.0.1"
			if family == "v6" {
				host = "fd13:5678::1"
			}
			for _, network := range []string{"tcp", "udp"} {
				runTUNApp(t, tunAppRequest{Network: network, Target: net.JoinHostPort(host, strconv.Itoa(ports[family+network])), Size: 4096, Concurrent: 4})
			}
		}
		for _, network := range []string{"udp", "tcp"} {
			runTUNApp(t, tunAppRequest{Network: network, Target: "198.19.0.53:53", DNS: true, Concurrent: 1})
		}
	}
	stopped := func() {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		if _, err := net.InterfaceByName(inbound.TUN.Interface); err == nil {
			t.Fatal("device retained")
		}
		if tunRouteSnapshot(t) != before {
			t.Fatal("routes/rules not restored")
		}
	}
	workload()
	stopped()
	runtime.GC()
	start := qfTUNSample(t, s, journal)
	peak := start
	for cycle := range 25 {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		workload()
		active := qfTUNSample(t, s, journal)
		peak.Goroutines = max(peak.Goroutines, active.Goroutines)
		peak.FDs = max(peak.FDs, active.FDs)
		peak.EventFDs = max(peak.EventFDs, active.EventFDs)
		peak.RSSKiB = max(peak.RSSKiB, active.RSSKiB)
		peak.Listeners = max(peak.Listeners, active.Listeners)
		peak.Sessions = max(peak.Sessions, active.Sessions)
		peak.Generations = max(peak.Generations, active.Generations)
		peak.Leases = max(peak.Leases, active.Leases)
		peak.HostGenerations = max(peak.HostGenerations, active.HostGenerations)
		peak.Interfaces = max(peak.Interfaces, active.Interfaces)
		peak.JournalTemporaries = max(peak.JournalTemporaries, active.JournalTemporaries)
		stopped()
		runtime.GC()
		end := qfTUNSample(t, s, journal)
		t.Logf("Native TUN lifetime=%d resources=%+v", cycle+1, end)
		if end.FDs != start.FDs || end.EventFDs != start.EventFDs || end.Goroutines != start.Goroutines || end.Sessions != 0 || end.Leases != start.Leases || end.Generations != start.Generations || end.HostGenerations != 0 || end.Interfaces != 0 || end.JournalTemporaries != 0 || end.Listeners != start.Listeners {
			t.Fatalf("strict resource equality failed: start=%+v end=%+v", start, end)
		}
	}
	end := qfTUNSample(t, s, journal)
	if queries.Load() == 0 || bootstrapQueries.Load() != 0 {
		t.Fatal("DNS detour/leak")
	}
	t.Logf("Native TUN real lifetimes=25 TCP/UDP/DNS IPv4/IPv6 route/policy PASS start=%+v peak=%+v end=%+v", start, peak, end)
}
