//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/hostnetwork"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/miekg/dns"
)

func TestPhase13TUNCrashOwner(t *testing.T) {
	requireOwnedTUNLab(t)
	var directory string
	if json.NewDecoder(os.Stdin).Decode(&directory) != nil {
		t.Fatal("missing crash fixture")
	}
	platform := hostnetwork.NewPlatform()
	store, err := hostnetwork.OpenStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	m, err := hostnetwork.New(platform, store)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := platform.Plan(context.Background(), client.TUNSettings{Interface: "splicore13crash", Addresses: []string{"198.18.4.1/30", "fd13:1234:4::1/126"}, MTU: 1500, AutoRoute: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := m.Prepare(context.Background(), plan.Records, func() error {
		d, e := platform.Device("splicore13crash")
		if e != nil {
			return e
		}
		return d.Start()
	})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM)
	fmt.Fprintln(os.Stdout, "owned-network-ready")
	<-stop
	if err = lease.Restore(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
}

func testTUNProcessRecovery(t *testing.T) {
	t.Helper()
	before := tunRouteSnapshot(t)
	for _, signal := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		directory := filepath.Join(t.TempDir(), "host-network")
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		command := exec.CommandContext(ctx, binary, "-test.run=^TestPhase13TUNCrashOwner$")
		command.Env = os.Environ()
		b, _ := json.Marshal(directory)
		command.Stdin = bytes.NewReader(b)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		stdout, err := command.StdoutPipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err = command.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || line != "owned-network-ready\n" {
			command.Process.Kill()
			command.Wait()
			cancel()
			t.Fatalf("crash owner readiness: %q %v %s", line, err, &stderr)
		}
		if err = command.Process.Signal(signal); err != nil {
			command.Process.Kill()
			command.Wait()
			cancel()
			t.Fatal(err)
		}
		err = command.Wait()
		cancel()
		if signal == syscall.SIGTERM && err != nil || signal == syscall.SIGKILL && err == nil {
			t.Fatalf("process termination %v: %v %s", signal, err, &stderr)
		}
		store, err := hostnetwork.OpenStore(directory)
		if err != nil {
			t.Fatal(err)
		}
		manager, err := hostnetwork.New(hostnetwork.NewPlatform(), store)
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		err = manager.Recover(context.Background())
		manager.Close()
		if err != nil {
			t.Fatal("next process recovery", signal, err)
		}
		if actual := tunRouteSnapshot(t); actual != before {
			t.Fatalf("process recovery did not exactly restore network: %v\n%s\n%s", signal, before, actual)
		}
	}
}

func requireOwnedTUNLab(t *testing.T) {
	t.Helper()
	ns, e := os.Readlink("/proc/self/ns/net")
	if e != nil || os.Getenv("SPLICORE_TUN_LAB") != "owned-disposable-network-namespace" || os.Getenv("SPLICORE_LAB_PARENT_NS") == "" || ns == os.Getenv("SPLICORE_LAB_PARENT_NS") {
		t.Fatal("real network tests require an explicitly owned disposable namespace")
	}
}

type tunAppRequest struct {
	Network, Target  string
	Size, Concurrent int
	DNS              bool
	Hold             bool
}

// Subprocess fixture sockets run under a different UID, so the daemon UID's
// underlay exception cannot accidentally make the application traffic bypass TUN.
func TestPhase13TUNApp(t *testing.T) {
	requireOwnedTUNLab(t)
	if os.Geteuid() != 65534 {
		t.Fatal("application fixture must use UID 65534")
	}
	var r tunAppRequest
	decoder := json.NewDecoder(os.Stdin)
	if decoder.Decode(&r) != nil {
		os.Exit(2)
	}
	if r.Hold {
		c, err := net.DialTimeout(r.Network, r.Target, 5*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer c.Close()
		for {
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte("held-flow-integrity"), 128)
			if _, err = c.Write(payload); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
			b := make([]byte, len(payload))
			if r.Network == "tcp" {
				_, err = io.ReadFull(c, b)
			} else {
				var n int
				n, err = c.Read(b)
				if n != len(b) {
					err = fmt.Errorf("held UDP size mismatch")
				}
			}
			if err != nil || !bytes.Equal(b, payload) {
				fmt.Fprintln(os.Stderr, "held integrity", err)
				os.Exit(2)
			}
			fmt.Fprintln(os.Stdout, "flow-ready")
			var command string
			if decoder.Decode(&command) != nil || command == "stop" {
				os.Exit(0)
			}
			if command != "again" {
				os.Exit(2)
			}
		}
	}
	failures := make(chan error, r.Concurrent)
	var workers sync.WaitGroup
	for i := 0; i < r.Concurrent; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if r.DNS {
				m := new(dns.Msg)
				m.SetQuestion("tun.proxy.test.", dns.TypeA)
				response, _, err := (&dns.Client{Net: r.Network, Timeout: 5 * time.Second}).ExchangeContext(ctx, m, r.Target)
				if err == nil && (response.Id != m.Id || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "198.19.0.1") {
					err = fmt.Errorf("intercepted DNS integrity mismatch")
				}
				failures <- err
				return
			}
			c, err := (&net.Dialer{}).DialContext(ctx, r.Network, r.Target)
			if err != nil {
				failures <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			payload := bytes.Repeat([]byte{byte(i), 17, 73, 91}, (r.Size+3)/4)[:r.Size]
			if r.Network == "tcp" {
				sent := make(chan error, 1)
				go func() { _, e := io.Copy(c, bytes.NewReader(payload)); sent <- e }()
				reply := make([]byte, len(payload))
				_, err = io.ReadFull(c, reply)
				writeErr := <-sent
				if err == nil {
					err = writeErr
				}
				if err == nil && !bytes.Equal(reply, payload) {
					err = fmt.Errorf("TCP integrity mismatch")
				}
			} else {
				for packet := 0; packet < 8; packet++ {
					if _, err = c.Write(payload); err != nil {
						break
					}
					reply := make([]byte, 65535)
					var n int
					n, err = c.Read(reply)
					if err == nil && !bytes.Equal(reply[:n], payload) {
						err = fmt.Errorf("UDP cross-talk")
					}
					if err != nil {
						break
					}
				}
			}
			failures <- err
		}(i)
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	fmt.Fprintln(os.Stdout, "application traffic integrity PASS")
	os.Exit(0)
}
func runTUNApp(t *testing.T, r tunAppRequest) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "-test.run=^TestPhase13TUNApp$")
	command.Env = os.Environ()
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	b, _ := json.Marshal(r)
	command.Stdin = bytes.NewReader(b)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("application %s %s: %v\n%s", r.Network, r.Target, err, output)
	}
}

func holdTUNApp(t *testing.T, r tunAppRequest) func(string) {
	t.Helper()
	r.Hold = true
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	command := exec.CommandContext(ctx, binary, "-test.run=^TestPhase13TUNApp$")
	command.Env = os.Environ()
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	input, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	encoder, reader := json.NewEncoder(input), bufio.NewReader(output)
	ready := func() {
		line, e := reader.ReadString('\n')
		if e != nil || line != "flow-ready\n" {
			t.Fatalf("held TUN app: %q %v", line, e)
		}
	}
	if err = encoder.Encode(r); err != nil {
		t.Fatal(err)
	}
	ready()
	t.Cleanup(func() {
		encoder.Encode("stop")
		input.Close()
		err := command.Wait()
		cancel()
		if err != nil {
			t.Errorf("held app exit: %v %s", err, &stderr)
		}
	})
	return func(command string) {
		t.Helper()
		if err := encoder.Encode(command); err != nil {
			t.Fatal(err)
		}
		ready()
	}
}

func testTUNPolicies(t *testing.T, s *application.Service, c P.Config, tunID identity.ID, outIDs map[string]identity.ID, ports map[string]int) {
	t.Helper()
	members := []P.Action{{Kind: P.Outbound, ID: outIDs["snell"]}, {Kind: P.Outbound, ID: outIDs["hysteria2"]}, {Kind: P.Outbound, ID: outIDs["tuic"]}}
	selector, lb, urlTest, fallback := networkID(t), networkID(t), networkID(t), networkID(t)
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer probe.Close()
	settings := P.Probe{URL: probe.URL, IntervalSeconds: 1, TimeoutSeconds: 2, ExpectedStatus: 204}
	c.Groups = []P.PolicyGroup{{ID: selector, Name: "TUN selector", Type: "selector", Members: members, Selector: &P.SelectorSettings{Selected: members[0]}}, {ID: lb, Name: "TUN balance", Type: "load_balance", Members: members, LoadBalance: &P.LoadBalanceSettings{Algorithm: "round_robin"}}, {ID: urlTest, Name: "TUN latency", Type: "url_test", Members: members, URLTest: &P.URLTestSettings{Probe: settings}}, {ID: fallback, Name: "TUN fallback", Type: "fallback", Members: members, Fallback: &P.FallbackSettings{Probe: settings}}}
	c.Route = P.RouteProfile{Final: &P.Action{Kind: P.Direct}, Rules: []P.RouteRule{{ID: networkID(t), Name: "TUN observed DNS domain", Match: P.RuleMatch{Domains: []string{"tun.proxy.test"}}, Action: P.Action{Kind: P.Group, ID: selector}}, {ID: networkID(t), Name: "TUN IPv6 CIDR", Match: P.RuleMatch{CIDRs: []string{"fd13:5678::/64"}}, Action: members[2]}}}
	applyNetwork(t, s, c)
	v4 := net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4tcp"]))
	v6 := net.JoinHostPort("fd13:5678::1", strconv.Itoa(ports["v6tcp"]))
	before := outboundSessions(t, s, outIDs["snell"])
	runTUNApp(t, tunAppRequest{Network: "tcp", Target: v4, Size: 4096, Concurrent: 1})
	if outboundSessions(t, s, outIDs["snell"]) != before+1 {
		t.Fatal("TUN observed domain route absent")
	}
	before = outboundSessions(t, s, outIDs["tuic"])
	runTUNApp(t, tunAppRequest{Network: "tcp", Target: v6, Size: 4096, Concurrent: 1})
	if outboundSessions(t, s, outIDs["tuic"]) != before+1 {
		t.Fatal("TUN CIDR route absent")
	}
	t.Run("retained_TCP_UDP_generation", func(t *testing.T) {
		tcp := holdTUNApp(t, tunAppRequest{Network: "tcp", Target: v4})
		udp := holdTUNApp(t, tunAppRequest{Network: "udp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4udp"]))})
		c.Groups[0].Selector.Selected = members[2]
		applyNetwork(t, s, c)
		tcp("again")
		udp("again")
		before := outboundSessions(t, s, outIDs["tuic"])
		runTUNApp(t, tunAppRequest{Network: "tcp", Target: v4, Size: 4096, Concurrent: 1})
		if outboundSessions(t, s, outIDs["tuic"]) != before+1 {
			t.Fatal("new TUN flow ignored committed selector")
		}
	})
	for _, group := range []identity.ID{urlTest, fallback, lb} {
		c.Route.Rules = []P.RouteRule{{ID: networkID(t), Name: "TUN group", Match: P.RuleMatch{LocalInbounds: []identity.ID{tunID}}, Action: P.Action{Kind: P.Group, ID: group}}}
		applyNetwork(t, s, c)
		if group != lb {
			policyObservation(t, s, group, func(g networkruntime.GroupStatus) bool { return g.Available })
		}
		runTUNApp(t, tunAppRequest{Network: "tcp", Target: v4, Size: 4096, Concurrent: 16})
		runTUNApp(t, tunAppRequest{Network: "udp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4udp"])), Size: 4096, Concurrent: 16})
		if group == lb {
			st, e := s.ClientStatus(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			for _, g := range st.Network.Groups {
				if g.ID == lb && g.Selections != 32 {
					t.Fatal("UDP packets changed flow affinity", g.Selections)
				}
			}
		}
	}
	t.Log("TUN Domain/CIDR; Selector, URL-Test, Fallback, Load-Balance; retained TCP/UDP and new generation; 16 UDP flows with packet affinity PASS")
}

func testTUNParallelIngress(t *testing.T, s *application.Service, outIDs map[string]identity.ID, ports map[string]int) {
	t.Helper()
	local := map[string]uint16{}
	ids := map[string]identity.ID{}
	for _, kind := range []string{"socks5", "http", "mixed"} {
		port := freePort(t)
		inbound := client.LocalInbound{Name: "simultaneous " + kind, Kind: kind, Listen: access.Endpoint{Host: "127.0.0.1", Port: port}, SelectedOutbound: outIDs["snell"]}
		result := clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &inbound})
		local[kind] = port
		ids[kind] = result.ID
	}
	status, err := s.ClientStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := status.State.Network
	for _, g := range c.Groups {
		if g.Type == "selector" {
			c.Route.Rules = append([]P.RouteRule{{ID: networkID(t), Name: "HTTP shared selector", Match: P.RuleMatch{LocalInbounds: []identity.ID{ids["http"]}}, Action: P.Action{Kind: P.Group, ID: g.ID}}}, c.Route.Rules...)
			break
		}
	}
	applyNetwork(t, s, c)
	before := outboundSessions(t, s, outIDs["tuic"])
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "HTTP-shared-policy-integrity") }))
	defer plain.Close()
	proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", local["http"]))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Get(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(payload) != "HTTP-shared-policy-integrity" || outboundSessions(t, s, outIDs["tuic"]) != before+1 {
		t.Fatal("HTTP proxy ignored shared policy", err)
	}
	target := access.Endpoint{Host: "198.19.0.1", Port: uint16(ports["v4tcp"])}
	failures := make(chan error, 3)
	go func() {
		failures <- transfer(local["socks5"], target, bytes.Repeat([]byte("SOCKS simultaneous"), 1024))
	}()
	for _, kind := range []string{"http", "mixed"} {
		go func(kind string) {
			conn, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", local[kind]), 5*time.Second)
			if e != nil {
				failures <- e
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			address := net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))
			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
			reader := bufio.NewReader(conn)
			r, e := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if e != nil {
				failures <- e
				return
			}
			if r.StatusCode != 200 {
				failures <- fmt.Errorf("CONNECT status %d", r.StatusCode)
				return
			}
			payload := bytes.Repeat([]byte(kind+" simultaneous"), 1024)
			_, e = conn.Write(payload)
			reply := make([]byte, len(payload))
			if e == nil {
				_, e = io.ReadFull(reader, reply)
			}
			if e == nil && !bytes.Equal(payload, reply) {
				e = fmt.Errorf("CONNECT integrity")
			}
			failures <- e
		}(kind)
	}
	runTUNApp(t, tunAppRequest{Network: "tcp", Target: net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))), Size: 4096, Concurrent: 16})
	for range 3 {
		if err := <-failures; err != nil {
			t.Fatal("simultaneous ingress", err)
		}
	}
	t.Log("shared server + SOCKS + HTTP + mixed + real TUN simultaneous; HTTP plain/CONNECT through shared policy/outbounds PASS")
}
func tunRouteSnapshot(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	for _, args := range [][]string{{"-j", "route", "show", "table", "all"}, {"-6", "-j", "route", "show", "table", "all"}, {"-j", "rule", "show"}, {"-6", "-j", "rule", "show"}} {
		b, e := exec.Command("ip", args...).Output()
		if e != nil {
			t.Fatal(e)
		}
		out.Write(b)
	}
	return out.String()
}
func tunResolver(t *testing.T, count *atomic.Int64) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{Listener: l, Net: "tcp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		count.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.19.0.1")}}
		_ = w.WriteMsg(m)
	})}
	ready, done := make(chan struct{}), make(chan error, 1)
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		server.Shutdown()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
}
func TestPhase13KernelTUN(t *testing.T) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
		return registry.NativeCore()
	})
	defer stop(t, s, store)
	cases := expansionCases(t)
	factories := []ports.OutboundFactory{}
	for _, c := range cases {
		factories = append(factories, c.factory)
	}
	adapters, err := registry.NewOutbounds(factories...)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.EnableClientRuntime(ctx, adapters, filepath.Join(root, "host-network")); err != nil {
		t.Fatal(err)
	}
	outIDs := map[string]identity.ID{"direct": client.Direct}
	for _, c := range cases {
		port := freePort(t)
		if c.transport == "quic" {
			port = udpPort(t)
		}
		created := expansionCreation(t, s, c, "127.0.0.1", port)
		node := expansionNode(t, s, c, access.Endpoint{Host: "127.0.0.1", Port: port}, expansionCredential(t, store, created, 0))
		outIDs[c.name] = expansionProxy(t, s, node, "native")
	}
	var ports map[string]int
	if json.Unmarshal([]byte(os.Getenv("SPLICORE_TUN_PORTS")), &ports) != nil {
		t.Fatal("missing namespace fixtures")
	}
	var directQueries, proxyQueries atomic.Int64
	directDNS := appDNS(t, "udp", &directQueries)
	proxyDNS := tunResolver(t, &proxyQueries)
	directID, proxyID := networkID(t), networkID(t)
	config := P.Config{Servers: []P.DNSServer{{ID: directID, Name: "bootstrap", Type: "udp", Endpoint: directDNS, Detour: P.Action{Kind: P.Direct}}, {ID: proxyID, Name: "proxy DNS", Type: "tcp", Endpoint: proxyDNS, Detour: P.Action{Kind: P.Outbound, ID: outIDs["snell"]}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: proxyID, BootstrapServer: directID, Strategy: "ipv4_only", TimeoutSeconds: 5, Cache: P.DNSCachePolicy{Capacity: 32}}}
	applyNetwork(t, s, config)
	tunID := networkID(t)
	inbound := client.LocalInbound{ID: tunID, Name: "owned namespace TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore13", Addresses: []string{"198.18.0.1/30", "fd13:1234::1/126"}, MTU: 1500, AutoRoute: true, DNSHijack: true, Stack: "gvisor"}}
	before := tunRouteSnapshot(t)
	document, _ := json.Marshal(application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &inbound})
	plan, err := s.PlanClient(ctx, document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApplyClient(ctx, application.ApplyRequest{Document: document, Digest: plan.Digest, Revision: plan.Revision}); err != nil {
		journal, _ := os.ReadFile(filepath.Join(root, "host-network", "journal.json"))
		t.Logf("owned synthetic journal: %s", journal)
		actual, readErr := hostnetwork.NewPlatform().Read(ctx, hostnetwork.Record{Kind: "rule", Family: 4, Priority: 10000, Table: 254})
		t.Logf("rule read diagnostic: %#v %v", actual, readErr)
		t.Logf("owned namespace routes: %s", tunRouteSnapshot(t))
		t.Fatal(err)
	}
	for _, name := range []string{"direct", "snell", "hysteria2", "tuic", "vless", "mieru"} {
		t.Run(name, func(t *testing.T) {
			clientApply(t, s, application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: outIDs[name]}})
			for _, fam := range []string{"v4", "v6"} {
				host := "198.19.0.1"
				if fam == "v6" {
					host = "fd13:5678::1"
				}
				for _, network := range []string{"tcp", "udp"} {
					runTUNApp(t, tunAppRequest{Network: network, Target: net.JoinHostPort(host, strconv.Itoa(ports[fam+network])), Size: 4096, Concurrent: 16})
				}
			}
			if name == "snell" {
				runTUNApp(t, tunAppRequest{Network: "tcp", Target: net.JoinHostPort("198.19.0.1", strconv.Itoa(ports["v4tcp"])), Size: 4 << 20, Concurrent: 1})
			}
			status, e := s.ClientStatus(ctx)
			if e != nil {
				t.Fatal(e)
			}
			observed := false
			for _, o := range status.Outbounds {
				if o.ID == outIDs[name] && o.Stats.Upload > 0 && o.Stats.Download > 0 && o.Stats.UDPAssociations > 0 {
					observed = true
				}
			}
			if !observed {
				t.Fatal("traffic bypassed TUN outbound counters", name)
			}
		})
	}
	for _, network := range []string{"udp", "tcp"} {
		runTUNApp(t, tunAppRequest{Network: network, Target: "198.19.0.53:53", DNS: true, Concurrent: 1})
	}
	if directQueries.Load() != 0 || proxyQueries.Load() < 1 {
		t.Fatal("DNS proxy detour/leak", directQueries.Load(), proxyQueries.Load())
	}
	testTUNPolicies(t, s, config, tunID, outIDs, ports)
	testTUNParallelIngress(t, s, outIDs, ports)
	for cycle := 0; cycle < 10; cycle++ {
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
		if _, err = net.InterfaceByName("splicore13"); err == nil {
			t.Fatal("TUN leaked")
		}
		if actual := tunRouteSnapshot(t); actual != before {
			t.Fatalf("route/rule restore mismatch\nbefore %s\nafter %s", before, actual)
		}
		clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "start"})
		runTUNApp(t, tunAppRequest{Network: "udp", Target: "198.19.0.53:53", DNS: true, Concurrent: 1})
	}
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	if actual := tunRouteSnapshot(t); actual != before {
		t.Fatal("final restore mismatch")
	}
	testTUNProcessRecovery(t)
	t.Log("IPv4/IPv6 TCP/UDP; DIRECT + five native outbound adapters; 4 MiB; 16 TCP/UDP; DNS proxy no leak; TUN/route/DNS lifecycle 10x PASS")
}
