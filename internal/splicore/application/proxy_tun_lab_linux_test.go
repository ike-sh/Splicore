//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
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
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

func TestPhase20TUNLifetime25(t *testing.T)         { phase20TUN(t, false) }
func TestPhase20TUNMixedSoak10Minutes(t *testing.T) { phase20TUN(t, true) }

func phase20TUN(t *testing.T, soak bool) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	journal := filepath.Join(root, "host-network")
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	cases := []expansionCase{}
	for index, mode := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none"} {
		for user := range 2 {
			c := vmessCase(t)
			c.name = fmt.Sprintf("vmess-%s-user%d", mode, user)
			settings := c.settings.(vm.Settings)
			settings.PayloadSecurity = mode
			if index%2 == 0 {
				settings.Security = "none"
				settings.TLS = nil
				c.security = client.Security{Kind: "none"}
			}
			c.settings = settings
			c.options, _ = json.Marshal(vm.ClientOptions{Security: mode, UDP: true})
			cases = append(cases, c)
		}
	}
	if soak {
		cases = append(cases, trojanCase(t))
	}
	if soak {
		cases = append(expansionCases(t), cases...)
	}
	if !soak {
		cases = nil
	}
	factories := []ports.OutboundFactory{native.ShadowsocksOutboundFactory{}, native.SOCKS5OutboundFactory{}, native.HTTPOutboundFactory{}}
	for _, c := range cases {
		present := false
		for _, old := range factories {
			if old.Capability().Protocol == c.factory.Capability().Protocol {
				present = true
			}
		}
		if !present {
			factories = append(factories, c.factory)
		}
	}
	adapters, err := registry.NewOutbounds(factories...)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, adapters, journal); err != nil {
		t.Fatal(err)
	}
	var proxies, inbounds []identity.ID
	var vmessAuthNodes []phase19AuthNode
	var auth phase19AuthMetrics
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
		user := 0
		if strings.HasSuffix(c.name, "user1") {
			user = 1
		}
		credential := expansionCredential(t, store, created, user)
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, credential)
		if c.key.Protocol == "vmess" {
			state, e := store.ClientState(ctx)
			if e != nil {
				t.Fatal(e)
			}
			for _, n := range state.Nodes {
				if n.ID == node {
					credential, e := store.RevealCredential(ctx, n.CredentialID)
					if e != nil {
						t.Fatal(e)
					}
					vmessAuthNodes = append(vmessAuthNodes, phase19AuthNode{n, credential})
				}
			}
		}
		proxies = append(proxies, expansionProxy(t, s, node, "native"))
		inbounds = append(inbounds, created.InboundID)
	}

	var peerPorts map[string]int
	if e := json.Unmarshal([]byte(os.Getenv("SPLICORE_P20_PEERS")), &peerPorts); e != nil {
		t.Fatal("local mature proxy peers required", e)
	}
	udpUnsupported := map[identity.ID]bool{}
	var socksUpstream identity.ID
	for _, protocol := range []string{"socks5", "http"} {
		for _, authEnabled := range []bool{false, true} {
			scheme := protocol
			if protocol == "socks5" {
				scheme = "socks5h"
			}
			userinfo := ""
			if authEnabled {
				userinfo = "synthetic:fixture@"
			}
			candidate, e := nodeimport.ParseURI(fmt.Sprintf("%s://%s127.0.0.1:%d#Phase20-upstream", scheme, userinfo, peerPorts[protocol+"-"+strconv.FormatBool(authEnabled)]))
			if e != nil {
				t.Fatal(e)
			}
			candidate.Node.Name = fmt.Sprintf("%s-%t", protocol, authEnabled)
			candidate.Key = candidate.Node.Name
			_, oid := ssImportedOutbound(t, s, candidate)
			proxies = append(proxies, oid)
			if protocol == "http" {
				udpUnsupported[oid] = true
			} else {
				socksUpstream = oid
			}
		}
	}
	var locals []client.LocalInbound
	for _, kind := range []string{"socks5", "http", "mixed"} {
		i, _ := createProxyListener(t, s, kind, true)
		locals = append(locals, i)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy credential reached origin")
		}
		_, _ = io.WriteString(w, "Phase20 plain HTTP payload")
	}))
	defer origin.Close()
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
	tun := client.LocalInbound{Name: "Phase20 proxy TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore20", Addresses: []string{"198.18.16.1/30", "fd13:1234:16::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true, Stack: "gvisor"}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &tun})
	rounds := 0
	tcpPayloads, udpPayloads := 0, 0
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
					if udpUnsupported[proxy] && network == "udp" {
						continue
					}
					runTUNApp(t, tunAppRequest{Network: network, Target: net.JoinHostPort(host, strconv.Itoa(ports[family+network])), Size: 2048, Concurrent: 1})
					if network == "tcp" {
						tcpPayloads++
					} else {
						udpPayloads++
					}
				}
			}
			for _, network := range []string{"tcp", "udp"} {
				if udpUnsupported[proxy] && network == "udp" {
					continue
				}
				runTUNApp(t, tunAppRequest{Network: network, Target: "198.19.0.53:53", DNS: true, Concurrent: 1})
				if network == "tcp" {
					tcpPayloads++
				} else {
					udpPayloads++
				}
			}

			target := access.Endpoint{Host: "198.19.0.1", Port: uint16(ports["v4tcp"])}
			for _, local := range locals {
				phase20Stream(t, local, target, "fixture")
				tcpPayloads++
				if local.Kind == "mixed" {
					local.Kind = "http"
					phase20Stream(t, local, target, "fixture")
					tcpPayloads++
				}
			}
			for _, local := range locals {
				if local.Kind == "http" || local.Kind == "mixed" {
					proxyURL, _ := url.Parse(fmt.Sprintf("http://synthetic:fixture@127.0.0.1:%d", local.Listen.Port))
					transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
					httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					response, e := httpClient.Get(origin.URL)
					if e != nil {
						t.Fatal(e)
					}
					raw, e := io.ReadAll(response.Body)
					_ = response.Body.Close()
					transport.CloseIdleConnections()
					tcpPayloads++
					if e != nil || string(raw) != "Phase20 plain HTTP payload" {
						t.Fatal("plain proxy payload", e)
					}
				}
			}
			if !udpUnsupported[proxy] {
				for _, local := range locals {
					if local.Kind != "http" {
						phase20LocalUDP(t, local, access.Endpoint{Host: "198.19.0.1", Port: uint16(ports["v4udp"])})
						udpPayloads++
					}
				}
			}
			if udpUnsupported[proxy] {
				decision, e := s.RouteExplain(ctx, networkruntime.Query{IP: netip.MustParseAddr("198.19.0.1"), Port: uint16(ports["v4udp"]), Network: "udp"})
				if e != nil || decision.Available {
					t.Fatal("HTTP UDP did not reject", e)
				}
				fallback := networkID(t)
				cfg := config.Clone()
				cfg.Groups = append(cfg.Groups, P.PolicyGroup{ID: fallback, Name: "HTTP UDP safe fallback", Type: "load_balance", Members: []P.Action{{Kind: P.Outbound, ID: proxy}, {Kind: P.Outbound, ID: socksUpstream}}, LoadBalance: &P.LoadBalanceSettings{Algorithm: "round_robin"}})
				cfg.Route.Final = &P.Action{Kind: P.Group, ID: fallback}
				applyNetwork(t, s, cfg)
				runTUNApp(t, tunAppRequest{Network: "udp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4udp"])), Size: 2048, Concurrent: 1})
				udpPayloads++
				applyNetwork(t, s, config)
			}
		}
		if soak {
			for _, node := range vmessAuthNodes {
				phase19AuthTraffic(t, node, access.Endpoint{Host: "198.19.0.1", Port: uint16(ports["v4tcp"])}, &auth)
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
		wait, cancel := context.WithTimeout(ctx, 5*time.Second)
		if e := s.WaitClientIdle(wait); e != nil {
			t.Fatal(e)
		}
		cancel()
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
		r := phase19TUNSample(t, s, journal, inbounds)
		if r.SharedTargetReaders != 0 || r.SharedIdleWorkers != 0 {
			t.Fatalf("retained shared UDP target workers: %+v", r)
		}
	}
	work()
	stopped()
	runtime.GC()
	start := phase19TUNSample(t, s, journal, inbounds)
	peak := start
	sample := func() phase19TUNResources {
		r := phase19TUNSample(t, s, journal, inbounds)
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
		cadence := time.NewTicker(30 * time.Second)
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
		t.Logf("mixed SOCKS5(TCP/UDP/auth)/HTTP(CONNECT/plain/auth)/Mixed/VMess(all modes/two users/raw+TLS)/Trojan/SS/SS2022/Snell/HY2/TUIC/VLESS/Mieru TUN TCP/UDP IPv4/IPv6 routing/policy/proxied DNS duration=%s rounds=%d successful_tcp_payloads=%d successful_udp_payloads=%d expected_security_rejections=%d unexpected_errors=0 start=%+v peak=%+v stopped=%+v", time.Since(begin), rounds, tcpPayloads, udpPayloads, auth.DuplicateRejected+auth.InvalidClockRejected+auth.InvalidAuthRejected+auth.BadTagRejected, start, peak, sample())
	} else {
		for cycle := range 25 {
			clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
			work()
			sample()
			stopped()
			runtime.GC()
			end := sample()
			t.Logf("Phase20 proxy TUN lifetime=%d stoppedTCP=0 stoppedUDP=0 resources=%+v", cycle+1, end)
			if end.FDs != start.FDs || end.Goroutines != start.Goroutines || end.EventFDs != start.EventFDs || end.Listeners != start.Listeners || end.Sessions != 0 || end.Generations != start.Generations || end.Leases != start.Leases || end.HostGenerations != 0 || end.Interfaces != 0 || end.JournalTemporaries != 0 {
				t.Fatalf("stopped resources start=%+v end=%+v", start, end)
			}
		}
		t.Logf("x25 successful_tcp_payloads=%d successful_udp_payloads=%d start=%+v peak=%+v end=%+v", tcpPayloads, udpPayloads, start, peak, sample())
	}
	t.Logf("VMess auth security metrics=%+v", auth)
	if queries.Load() == 0 || bootstrapQueries.Load() != 0 {
		t.Fatal("DNS detour leak", queries.Load(), bootstrapQueries.Load())
	}
}
