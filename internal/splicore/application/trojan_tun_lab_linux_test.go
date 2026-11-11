//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestPhase18TUNLifetime25(t *testing.T)         { phase18TUN(t, false) }
func TestPhase18TUNMixedSoak10Minutes(t *testing.T) { phase18TUN(t, true) }

// The lab runs in disposable mount/network namespaces. Resource observations
// belong to tests; no production sampling or diagnostic worker is added.
func phase18TUN(t *testing.T, soak bool) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	journal := filepath.Join(root, "host-network")
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	cases := []expansionCase{trojanCase(t)}
	if soak {
		cases = append(expansionCases(t), cases...)
	}
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
	var trojanNode client.RemoteNode
	var trojanCredential access.Credential
	methods := []string{}
	if soak {
		methods = []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"}
	}
	for _, method := range methods {
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
		credential := expansionCredential(t, store, created, 0)
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, credential)
		if c.name == "trojan" {
			state, err := store.ClientState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, n := range state.Nodes {
				if n.ID == node {
					trojanNode = n
				}
			}
			trojanCredential, err = store.RevealCredential(ctx, trojanNode.CredentialID)
			if err != nil {
				t.Fatal(err)
			}
		}
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
	tun := client.LocalInbound{Name: "Phase18 mixed TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore18", Addresses: []string{"198.18.16.1/30", "fd13:1234:16::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true, Stack: "gvisor"}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &tun})
	rounds := 0
	idleRecreations := 0
	work := func() {
		for _, proxy := range proxies {
			config.Groups[0].Selector.Selected = P.Action{Kind: P.Outbound, ID: proxy}
			config.Servers[1].Detour = P.Action{Kind: P.Outbound, ID: proxy}
			applyNetwork(t, s, config)
			if soak && proxy == proxies[len(proxies)-1] {
				phase18RealTargetIdle(t, trojanNode, trojanCredential, ports)
				idleRecreations++
			}
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
		r := phase18TUNSample(t, s, journal, inbounds)
		if r.SharedTargetReaders != 0 || r.SharedIdleWorkers != 0 {
			t.Fatalf("retained shared UDP target workers: %+v", r)
		}
	}
	work()
	stopped()
	runtime.GC()
	start := phase18TUNSample(t, s, journal, inbounds)
	peak := start
	sample := func() phase18TUNResources {
		r := phase18TUNSample(t, s, journal, inbounds)
		peak.Goroutines = max(peak.Goroutines, r.Goroutines)
		peak.FDs = max(peak.FDs, r.FDs)
		peak.RSSKiB = max(peak.RSSKiB, r.RSSKiB)
		peak.EventFDs = max(peak.EventFDs, r.EventFDs)
		peak.Listeners = max(peak.Listeners, r.Listeners)
		peak.Sessions = max(peak.Sessions, r.Sessions)
		peak.TCPActive = max(peak.TCPActive, r.TCPActive)
		peak.UDPActive = max(peak.UDPActive, r.UDPActive)
		peak.SharedTargetReaders = max(peak.SharedTargetReaders, r.SharedTargetReaders)
		peak.SharedIdleWorkers = max(peak.SharedIdleWorkers, r.SharedIdleWorkers)
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
		t.Logf("mixed Trojan/SS/SS2022/Snell/HY2/TUIC/VLESS/Mieru TUN TCP/UDP IPv4/IPv6 routing/policy/proxied DNS duration=%s rounds=%d actual_target_expirations=%d same_association_recreations=%d expected_errors=0 unexpected_errors=0 start=%+v peak=%+v stopped=%+v", time.Since(begin), rounds, idleRecreations, idleRecreations, start, peak, sample())
	} else {
		for cycle := range 25 {
			clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
			work()
			sample()
			stopped()
			runtime.GC()
			end := sample()
			t.Logf("Phase18 Trojan TUN lifetime=%d TCP=0 UDP=0 resources=%+v", cycle+1, end)
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

type phase18TUNResources struct {
	qfTUNResources
	TCPActive, UDPActive, TCPTotal, UDPTotal int64
	SharedTargetReaders, SharedIdleWorkers   int
}

func phase18TUNSample(t *testing.T, s *application.Service, journal string, inbounds []identity.ID) phase18TUNResources {
	t.Helper()
	r := phase18TUNResources{qfTUNResources: qfTUNSample(t, s, journal)}
	stack := make([]byte, 4<<20)
	n := runtime.Stack(stack, true)
	r.SharedTargetReaders = bytes.Count(stack[:n], []byte("relay.(*packetRelay).read("))
	r.SharedIdleWorkers = bytes.Count(stack[:n], []byte("relay.(*packetRelay).watchIdle("))
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

// This runs beside real UID-isolated TUN traffic in the disposable lab. One
// authenticated Trojan association holds A and B; B keeps the parent alive while
// A's connected kernel UDP socket must vanish, then be recreated under the same
// destination. Kernel inode checks distinguish expiry from successful writes.
func phase18RealTargetIdle(t *testing.T, node client.RemoteNode, credential access.Credential, ports map[string]int) {
	t.Helper()
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	d, err := (native.TrojanOutboundFactory{}).Build(ctx, node, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	a := access.Endpoint{Host: "198.19.0.1", Port: uint16(ports["v4udp"])}
	b := access.Endpoint{Host: "fd13:5678::1", Port: uint16(ports["v6udp"])}
	p, err := d.(portsClientPacketDialer).ListenPacket(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	exchange := func(dst access.Endpoint, tag byte) {
		t.Helper()
		data := []byte{tag, 18, 1, 73}
		if err := p.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if n, err := p.WriteTo(data, netaddr.UDP(dst)); err != nil || n != len(data) {
			t.Fatal("idle lifecycle write", err)
		}
		buffer := make([]byte, 65535)
		n, addr, err := p.ReadFrom(buffer)
		endpoint, _ := netaddr.From(addr)
		if err != nil || endpoint != dst || !bytes.Equal(buffer[:n], data) {
			t.Fatal("idle lifecycle actual reply", err)
		}
	}
	before := phase18UDPSocketInodes(t, a.Port)
	exchange(a, 181)
	first := phase18NewInode(t, before, phase18UDPSocketInodes(t, a.Port))
	begin := time.Now()
	for time.Since(begin) < 6*time.Second {
		exchange(b, 182)
		time.Sleep(200 * time.Millisecond)
	}
	after := phase18UDPSocketInodes(t, a.Port)
	if after[first] {
		t.Fatal("quiet target kernel socket retained while sibling keeps association alive")
	}
	exchange(a, 181)
	replacement := phase18NewInode(t, after, phase18UDPSocketInodes(t, a.Port))
	if first == replacement {
		t.Fatal("expired socket inode reused")
	}
	for range 4 {
		exchange(a, 181)
		exchange(b, 182)
	}
	t.Logf("real Trojan target idle=%s first_inode=%s replacement_inode=%s expired=1 recreated=1 same_TLS_association=true sibling_replies=true repeated_replies=4 unexpected=0", time.Since(begin), first, replacement)
}

type portsClientPacketDialer interface {
	ListenPacket(context.Context, access.Endpoint) (net.PacketConn, error)
}

func phase18UDPSocketInodes(t *testing.T, port uint16) map[string]bool {
	t.Helper()
	result := map[string]bool{}
	for _, name := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			remote := strings.Split(fields[2], ":")
			if len(remote) != 2 {
				continue
			}
			value, err := strconv.ParseUint(remote[1], 16, 16)
			if err == nil && uint16(value) == port {
				result[fields[9]] = true
			}
		}
	}
	return result
}
func phase18NewInode(t *testing.T, before, after map[string]bool) string {
	t.Helper()
	found := ""
	for inode := range after {
		if !before[inode] {
			if found != "" {
				t.Fatal("ambiguous new target sockets", fmt.Sprint(before), fmt.Sprint(after))
			}
			found = inode
		}
	}
	if found == "" {
		t.Fatal("no new connected target socket")
	}
	return found
}
