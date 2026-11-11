//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

type qfTUNResources struct {
	Goroutines, FDs, SocketFDs, EventFDs, Listeners, Sessions, Generations, Leases int
	HostGenerations, Interfaces, JournalTemporaries                                int
	RSSKiB                                                                         int
}

func qfTUNSample(t *testing.T, s *application.Service, journal string) qfTUNResources {
	t.Helper()
	st, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := qfTUNResources{Goroutines: runtime.NumGoroutine(), Sessions: len(st.Sessions), Generations: len(st.Underlay.Generations), Leases: st.Underlay.ActiveLeases, HostGenerations: st.Host.ActiveGenerations, Interfaces: st.Host.OwnedInterfaces}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmRSS:" {
			r.RSSKiB, err = strconv.Atoi(fields[1])
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if os.IsNotExist(err) { // The directory enumeration's own FD is closed.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		r.FDs++
		if strings.HasPrefix(target, "socket:") {
			r.SocketFDs++
		}
		if target == "anon_inode:[eventfd]" {
			r.EventFDs++
		}
	}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) > 3 && fields[3] == "0A" {
				r.Listeners++
			}
		}
	}
	files, err := os.ReadDir(journal)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.Contains(file.Name(), ".tmp") {
			r.JournalTemporaries++
		}
	}
	return r
}

// Fix-stage stress only: ten active one-minute workloads, each with an owned
// TUN lifetime. This is not Platform Qualification or its 60-minute soak.
func TestQF001TUNBoundedStress(t *testing.T) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	journal := filepath.Join(root, "host-network")
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	c := expansionCases(t)[0] // Existing synthetic Snell fixture.
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
	var queries atomic.Int64
	resolver := tunResolver(t, &queries)
	dnsID, bootstrapID := networkID(t), networkID(t)
	var bootstrapQueries atomic.Int64
	bootstrap := appDNS(t, "udp", &bootstrapQueries)
	config := P.Config{Servers: []P.DNSServer{{ID: bootstrapID, Name: "QF bootstrap", Type: "udp", Endpoint: bootstrap, Detour: P.Action{Kind: P.Direct}}, {ID: dnsID, Name: "QF synthetic DNS", Type: "tcp", Endpoint: resolver, Detour: P.Action{Kind: P.Outbound, ID: proxy}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: dnsID, BootstrapServer: bootstrapID, Strategy: "ipv4_only", TimeoutSeconds: 5, Cache: P.DNSCachePolicy{Capacity: 32}}}
	groupID := networkID(t)
	config.Groups = []P.PolicyGroup{{ID: groupID, Name: "Native TUN stress selector", Type: "selector", Members: []P.Action{{Kind: P.Direct}, {Kind: P.Outbound, ID: proxy}}, Selector: &P.SelectorSettings{Selected: P.Action{Kind: P.Direct}}}}
	config.Route.Final = &P.Action{Kind: P.Group, ID: groupID}
	applyNetwork(t, s, config)
	var ports map[string]int
	if err := json.Unmarshal([]byte(os.Getenv("SPLICORE_TUN_PORTS")), &ports); err != nil {
		t.Fatal(err)
	}
	before := tunRouteSnapshot(t)
	tun := client.LocalInbound{Name: "QF owned TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicoreqf1", Addresses: []string{"198.18.12.1/30", "fd13:1234:12::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true, Stack: "gvisor"}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &tun})
	round := func() {
		var workers sync.WaitGroup
		for _, request := range []tunAppRequest{
			{Network: "tcp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4tcp"])), Size: 64 << 10, Concurrent: 16},
			{Network: "udp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4udp"])), Size: 4096, Concurrent: 16},
			{Network: "udp", Target: "198.19.0.53:53", DNS: true, Concurrent: 16},
		} {
			workers.Go(func() { runTUNApp(t, request) })
		}
		workers.Wait()
		if t.Failed() {
			t.Fatal("bounded workload failed; no retry")
		}
	}
	stopTUN := func() {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		if _, err := net.InterfaceByName(tun.TUN.Interface); err == nil {
			t.Fatal("owned TUN interface remains after stop")
		}
		if tunRouteSnapshot(t) != before {
			t.Fatal("owned route/rule snapshot not restored")
		}
	}
	// Warm the runtime/standard-library caches before measuring retained resources.
	round()
	stopTUN()
	// Measure CLOSED against CLOSED: closing the journal intentionally releases
	// its descriptor. A STOPPED Manager still owns that journal and one disabled
	// generation, so it is a different resource state.
	if err := s.CloseClientRuntime(ctx); err != nil {
		t.Fatal(err)
	}
	closedBaseline := qfTUNSample(t, s, journal)
	if err := s.EnableClientRuntime(ctx, adapters, journal); err != nil {
		t.Fatal(err)
	}
	start := qfTUNSample(t, s, journal)
	t.Logf("QF stopped baseline resources=%+v", start)
	peak := start
	workloadStart := time.Now()
	totalRounds := 0
	var activeDuration time.Duration
	for cycle := range 10 {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		cycleStart := time.Now()
		for time.Since(cycleStart) < time.Minute {
			selected := P.Action{Kind: P.Direct}
			if totalRounds%2 == 0 {
				selected = P.Action{Kind: P.Outbound, ID: proxy}
			}
			// Commit a fresh generation while the same device/stack remains owned.
			config.Groups[0].Selector.Selected = selected
			applyNetwork(t, s, config)
			round()
			totalRounds++
			r := qfTUNSample(t, s, journal)
			peak.Goroutines = max(peak.Goroutines, r.Goroutines)
			peak.FDs = max(peak.FDs, r.FDs)
			peak.SocketFDs = max(peak.SocketFDs, r.SocketFDs)
			peak.EventFDs = max(peak.EventFDs, r.EventFDs)
			peak.Listeners = max(peak.Listeners, r.Listeners)
			peak.Sessions = max(peak.Sessions, r.Sessions)
			peak.Generations = max(peak.Generations, r.Generations)
			peak.Leases = max(peak.Leases, r.Leases)
			peak.HostGenerations = max(peak.HostGenerations, r.HostGenerations)
			peak.Interfaces = max(peak.Interfaces, r.Interfaces)
			peak.JournalTemporaries = max(peak.JournalTemporaries, r.JournalTemporaries)
			peak.RSSKiB = max(peak.RSSKiB, r.RSSKiB)
		}
		activeDuration += time.Since(cycleStart)
		stopTUN()
		end := qfTUNSample(t, s, journal)
		t.Logf("QF cycle=%d rounds=%d resources=%+v", cycle+1, totalRounds, end)
		// Runtime stop publishes a disabled snapshot owning one underlay lease;
		// it must match the stopped baseline, with no retained traffic generations.
		if end.Sessions != 0 || end.Generations != start.Generations || end.Leases != start.Leases || end.HostGenerations != 0 || end.Interfaces != 0 || end.JournalTemporaries != 0 || end.Listeners != start.Listeners || end.EventFDs != start.EventFDs || end.FDs != start.FDs {
			t.Fatalf("owned lifecycle resource residue: %+v", end)
		}
	}
	closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.CloseClientRuntime(closeCtx); err != nil {
		t.Fatal(err)
	}
	end := qfTUNSample(t, s, journal)
	if end.Sessions != 0 || end.Generations != 0 || end.Leases != 0 || end.HostGenerations != 0 || end.Interfaces != 0 || end.JournalTemporaries != 0 {
		t.Fatalf("closed client ownership residue: %+v", end)
	}
	if queries.Load() == 0 || bootstrapQueries.Load() != 0 {
		t.Fatalf("DNS detour/leak: upstream=%d bootstrap=%d", queries.Load(), bootstrapQueries.Load())
	}
	t.Logf("QF fix-stage bounded stress wall=%s active=%s rounds=%d TCP_flows=%d UDP_flows=%d UDP_echoes=%d DNS_replies=%d upstream_queries=%d start=%+v peak=%+v end=%+v", time.Since(workloadStart), activeDuration, totalRounds, totalRounds*16, totalRounds*16, totalRounds*16*8, totalRounds*16, queries.Load(), start, peak, end)
	// Report all descriptors, including upstream dispatcher eventfds. Cache
	// allowances must never hide an FD retained once per TUN lifetime.
	if end.Goroutines != closedBaseline.Goroutines || end.SocketFDs != closedBaseline.SocketFDs || end.FDs != closedBaseline.FDs || end.EventFDs != closedBaseline.EventFDs {
		t.Fatal(fmt.Sprintf("closed resource mismatch: baseline=%+v end=%+v", closedBaseline, end))
	}
}
