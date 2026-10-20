package clientruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/miekg/dns"
)

// These tests must remain serial: the trap replaces the process-wide resolver.
// Register restoration before managers so their sessions finish before restore.
func trapTunnelSystemDNS(t *testing.T, answer *access.Endpoint) *atomic.Int64 {
	t.Helper()
	count := new(atomic.Int64)
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		count.Add(1)
		if answer != nil {
			return (&net.Dialer{}).DialContext(ctx, network, tunnelAddress(*answer))
		}
		return nil, errors.New("test forbids system DNS")
	}}
	t.Cleanup(func() { net.DefaultResolver = previous })
	return count
}

type tunnelDNSProbe struct {
	queries, unexpected atomic.Int64
	entered             chan struct{}
}

func tunnelDNS(t *testing.T, rcode int, silent bool) (access.Endpoint, *tunnelDNSProbe) {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	probe := &tunnelDNSProbe{entered: make(chan struct{}, 64)}
	ready, done := make(chan struct{}), make(chan error, 1)
	server := &dns.Server{PacketConn: packet, Net: "udp", NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		probe.queries.Add(1)
		select {
		case probe.entered <- struct{}{}:
		default:
		}
		if q.Question[0].Name != "guard-target.test." || q.Question[0].Qtype != dns.TypeA {
			probe.unexpected.Add(1)
		}
		if silent {
			return
		}
		reply := new(dns.Msg)
		reply.SetRcode(q, rcode)
		if rcode == dns.RcodeSuccess && q.Question[0].Name == "guard-target.test." && q.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
		}
		_ = w.WriteMsg(reply)
	})}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("DNS fixture startup timed out")
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(packet.LocalAddr().(*net.UDPAddr).Port)}, probe
}

func configureTunnelDNS(t *testing.T, state *client.ProfileState, endpoint access.Endpoint) {
	t.Helper()
	id := tunnelID(t)
	state.Network.Servers = []P.DNSServer{{ID: id, Name: "Core target resolver", Type: "udp", Endpoint: endpoint, Detour: P.Action{Kind: P.Direct}}}
	state.Network.DNS = P.DNSProfile{Enabled: true, DefaultServer: id, BootstrapServer: id, Strategy: "ipv4_only", TimeoutSeconds: 1, Cache: P.DNSCachePolicy{Capacity: 8}}
}

func tunnelDNSIdle(t *testing.T, m *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := m.WaitIdle(ctx); err != nil {
		t.Fatal("session/resolver did not finish", err)
	}
}

func TestTunnelCoreDNSParityAndGuard(t *testing.T) {
	system := trapTunnelSystemDNS(t, nil)
	resolver, probe := tunnelDNS(t, dns.RcodeSuccess, false)
	target, dials := countedTunnelTarget(t)
	target.Host = "guard-target.test"
	state := tunnelState(t, target, "127.0.0.1")
	configureTunnelDNS(t, &state, resolver)
	control := client.LocalInbound{ID: tunnelID(t), Name: "SOCKS DNS control", Kind: "socks5", Listen: tunnelPort(t, "127.0.0.1")}
	state.LocalInbounds = append(state.LocalInbounds, control)
	m := startTunnel(t, state)
	hello := testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13)
	t.Run("SOCKS", func(t *testing.T) {
		c, err := net.Dial("tcp", tunnelAddress(control.Listen))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err = socks.Handshake(c, socks.Connect, target); err != nil {
			t.Fatal(err)
		}
		if _, err = c.Write(hello); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(hello))
		if _, err = io.ReadFull(c, got); err != nil || string(got) != string(hello) {
			t.Fatal("SOCKS Core DNS control failed", err)
		}
		c.Close()
		tunnelDNSIdle(t, m)
		if probe.queries.Load() == 0 || system.Load() != 0 || dials.Load() != 1 {
			t.Fatal("SOCKS bypassed Core DNS", probe.queries.Load(), system.Load(), dials.Load())
		}
	})
	t.Run("TunnelRouteOnly", func(t *testing.T) {
		if err := m.FlushDNS(); err != nil {
			t.Fatal(err)
		}
		before, beforeDials := probe.queries.Load(), dials.Load()
		err := tunnelExchange(state.LocalInbounds[0].Listen, hello, false)
		tunnelDNSIdle(t, m)
		t.Logf("Core queries=%d, system queries=%d, target connections=%d", probe.queries.Load()-before, system.Load(), dials.Load()-beforeDials)
		if err != nil || probe.queries.Load() <= before || system.Load() != 0 || dials.Load() != beforeDials+1 || probe.unexpected.Load() != 0 {
			t.Fatal("tunnel must resolve only configured host through Core DNS", err)
		}
		gen := m.acquire()
		configured := gen.state.LocalInbounds[0].Tunnel.Target
		gen.release()
		if configured != target {
			t.Fatal("routeOnly changed configured host/port", configured)
		}
	})
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"WrongSNI", testkit.ClientHello(t, "wrong.test", tls.VersionTLS13)},
		{"MissingSNI", testkit.ClientHello(t, "", tls.VersionTLS13)},
		{"HTTP", []byte("GET / HTTP/1.1\r\nHost: approved-b.test\r\n\r\n")},
		{"MalformedTLS", []byte{22, 3, 3, 0, 1, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.FlushDNS(); err != nil {
				t.Fatal(err)
			}
			before, beforeDials := probe.queries.Load(), dials.Load()
			beforeSystem := system.Load()
			beforeLookups := m.NetworkStatus().DNS.Queries
			err := tunnelExchange(state.LocalInbounds[0].Listen, tc.data, false)
			tunnelDNSIdle(t, m)
			if err == nil || probe.queries.Load() != before || dials.Load() != beforeDials || system.Load() != beforeSystem || m.NetworkStatus().DNS.Queries != beforeLookups {
				t.Fatal("denied input caused resolution or upstream dial", err)
			}
		})
	}
}

func TestTunnelCoreDNSNXDOMAINNoFallback(t *testing.T) {
	// Prove that the intercepted OS path *can* resolve this name, then forbid
	// any use of it when Core DNS authoritatively returns NXDOMAIN.
	systemEndpoint, _ := tunnelDNS(t, dns.RcodeSuccess, false)
	system := trapTunnelSystemDNS(t, &systemEndpoint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "guard-target.test")
	if err != nil || len(ips) == 0 || !ips[0].Equal(net.ParseIP("127.0.0.1")) || system.Load() == 0 {
		t.Fatal("system fallback positive control failed", err)
	}
	system.Store(0)
	resolver, probe := tunnelDNS(t, dns.RcodeNameError, false)
	target, dials := countedTunnelTarget(t)
	target.Host = "guard-target.test"
	state := tunnelState(t, target, "127.0.0.1")
	configureTunnelDNS(t, &state, resolver)
	m := startTunnel(t, state)
	err = tunnelExchange(state.LocalInbounds[0].Listen, testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13), false)
	tunnelDNSIdle(t, m)
	t.Logf("Core NXDOMAIN queries=%d, system queries=%d, target connections=%d", probe.queries.Load(), system.Load(), dials.Load())
	if err == nil || probe.queries.Load() == 0 || system.Load() != 0 || dials.Load() != 0 {
		t.Fatal("Core NXDOMAIN must fail without system fallback", err)
	}
}

func TestTunnelCoreDNSIPLiteral(t *testing.T) {
	system := trapTunnelSystemDNS(t, nil)
	resolver, probe := tunnelDNS(t, dns.RcodeNameError, false)
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			target, dials := countedTunnelTarget(t)
			if host == "::1" {
				// The existing IPv6 listener path is exercised by the same guard;
				// use a genuine IPv6 upstream as well.
				l, err := net.Listen("tcp", "[::1]:0")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					c, err := l.Accept()
					if err == nil {
						defer c.Close()
						dials.Add(1)
						_ = c.SetDeadline(time.Now().Add(3 * time.Second))
						io.Copy(c, c)
						c.(*net.TCPConn).CloseWrite()
					}
				}()
				t.Cleanup(func() { l.Close(); <-done })
				target = tunnelEndpoint(l.Addr())
			}
			state := tunnelState(t, target, host)
			configureTunnelDNS(t, &state, resolver)
			m := startTunnel(t, state)
			if err := tunnelExchange(state.LocalInbounds[0].Listen, testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13), false); err != nil {
				t.Fatal(err)
			}
			tunnelDNSIdle(t, m)
			if dials.Load() != 1 || probe.queries.Load() != 0 || system.Load() != 0 {
				t.Fatal("IP literal must not use DNS")
			}
		})
	}
}

func TestTunnelCoreDNSConcurrent(t *testing.T) {
	system := trapTunnelSystemDNS(t, nil)
	resolver, probe := tunnelDNS(t, dns.RcodeSuccess, false)
	target, dials := countedTunnelTarget(t)
	target.Host = "guard-target.test"
	state := tunnelState(t, target, "127.0.0.1")
	configureTunnelDNS(t, &state, resolver)
	m := startTunnel(t, state)
	hello := testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range cap(errs) {
		wg.Go(func() { errs <- tunnelExchange(state.LocalInbounds[0].Listen, hello, false) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	tunnelDNSIdle(t, m)
	if dials.Load() != 16 || probe.queries.Load() == 0 || probe.unexpected.Load() != 0 || system.Load() != 0 {
		t.Fatal("concurrent Core resolution failed", dials.Load(), probe.queries.Load(), system.Load())
	}
}

func TestTunnelCoreDNSCancellation(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			system := trapTunnelSystemDNS(t, nil)
			resolver, probe := tunnelDNS(t, dns.RcodeSuccess, true)
			target, dials := countedTunnelTarget(t)
			target.Host = "guard-target.test"
			state := tunnelState(t, target, "127.0.0.1")
			configureTunnelDNS(t, &state, resolver)
			if mode != "timeout" {
				state.Network.DNS.TimeoutSeconds = 10
			}
			m := startTunnel(t, state)
			c, err := net.Dial("tcp", tunnelAddress(state.LocalInbounds[0].Listen))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := c.Write(testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-probe.entered:
			case <-time.After(time.Second):
				t.Fatal("tunnel did not enter Core resolver")
			}
			start := time.Now()
			switch mode {
			case "cancel":
				m.mu.Lock()
				for _, s := range m.sessions {
					s.cancel()
				}
				m.mu.Unlock()
			case "shutdown":
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := m.Close(ctx); err != nil {
					t.Fatal("shutdown leaked resolving session", err)
				}
			}
			var b [1]byte
			_, err = c.Read(b[:])
			if nerr, ok := err.(net.Error); err == nil || ok && nerr.Timeout() {
				t.Fatal("resolution did not terminate cleanly", err)
			}
			tunnelDNSIdle(t, m)
			if mode != "timeout" && time.Since(start) >= time.Second {
				t.Fatal("connection context did not cancel DNS promptly")
			}
			if system.Load() != 0 || dials.Load() != 0 {
				t.Fatal("failed resolution attempted system DNS or target dial")
			}
		})
	}
}
