package clientruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/engine/sniff"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func tunnelID(t *testing.T) identity.ID {
	t.Helper()
	id, e := identity.NewID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}

func tunnelEndpoint(a net.Addr) access.Endpoint {
	p := a.(*net.TCPAddr)
	return access.Endpoint{Host: p.IP.String(), Port: uint16(p.Port)}
}
func tunnelAddress(e access.Endpoint) string { return net.JoinHostPort(e.Host, fmt.Sprint(e.Port)) }
func tunnelPort(t *testing.T, host string) access.Endpoint {
	t.Helper()
	l, e := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if e != nil {
		t.Fatal(e)
	}
	p := tunnelEndpoint(l.Addr())
	l.Close()
	return p
}

func tunnelState(t *testing.T, target access.Endpoint, host string) client.ProfileState {
	t.Helper()
	id := tunnelID(t)
	s := client.Empty()
	s.LocalInbounds = []client.LocalInbound{{ID: id, Name: "local guard", Kind: "tunnel", Listen: tunnelPort(t, host), Tunnel: &client.TunnelSettings{Target: target, Network: "tcp"}, Sniffing: &client.SniffingPolicy{Enabled: true, Protocols: []string{"tls"}, RouteOnly: true}}}
	s.Network.Route.Rules = []P.RouteRule{
		{ID: tunnelID(t), Name: "allow exact visible SNI", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}, SniffedDomains: []string{"www.3verge.com", "approved-b.test"}}, Action: P.Action{Kind: P.Direct}},
		{ID: tunnelID(t), Name: "guard fallback", Match: P.RuleMatch{LocalInbounds: []identity.ID{id}}, Action: P.Action{Kind: P.Reject}},
	}
	return s
}

func startTunnel(t *testing.T, state client.ProfileState) *Manager {
	t.Helper()
	m := New()
	r, e := registry.NewOutbounds()
	if e != nil {
		t.Fatal(e)
	}
	p, e := m.Prepare(context.Background(), state, nil, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Activate(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := m.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return m
}

func countedTunnelTarget(t *testing.T) (access.Endpoint, *atomic.Int64) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	count := &atomic.Int64{}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			count.Add(1)
			wg.Go(func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(c, c)
				if tcp, ok := c.(*net.TCPConn); ok {
					tcp.CloseWrite()
				}
			})
		}
	})
	t.Cleanup(func() { l.Close(); wg.Wait() })
	return tunnelEndpoint(l.Addr()), count
}

func tunnelExchange(endpoint access.Endpoint, payload []byte, fragment bool) error {
	c, e := net.DialTimeout("tcp", tunnelAddress(endpoint), time.Second)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	if fragment {
		for start := 0; start < len(payload); {
			end := min(start+37, len(payload))
			if _, e = c.Write(payload[start:end]); e != nil {
				return e
			}
			start = end
			time.Sleep(time.Millisecond)
		}
	} else {
		if _, e = c.Write(payload); e != nil {
			return e
		}
	}
	if e = c.(*net.TCPConn).CloseWrite(); e != nil {
		return e
	}
	got, e := io.ReadAll(c)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("replay mismatch: sent %d received %d", len(payload), len(got))
	}
	return nil
}

func TestTunnelGuardSecurityMatrix(t *testing.T) {
	target, count := countedTunnelTarget(t)
	state := tunnelState(t, target, "127.0.0.1")
	m := startTunnel(t, state)
	endpoint := state.LocalInbounds[0].Listen
	valid := testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS13)
	recordFragment := append([]byte{22, 3, 1, 0, 2}, valid[5:7]...)
	rest := valid[7:]
	recordFragment = append(recordFragment, 22, 3, 3, byte(len(rest)>>8), byte(len(rest)))
	recordFragment = append(recordFragment, rest...)
	malformed := append([]byte(nil), valid...)
	malformed[5] = 2
	empty := append([]byte(nil), valid...)
	// Same-size invalid SNI avoids relying on a TLS library accepting malformed names.
	copy(empty[bytes.Index(empty, []byte("www.3verge.com")):], []byte("www.3verge..om"))
	cases := []struct {
		name                  string
		data                  []byte
		allow, fragment, slow bool
	}{
		{"valid TLS13", valid, true, false, false},
		{"valid TLS12", testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS12), true, false, false},
		{"approved B", testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13), true, false, false},
		{"uppercase", testkit.ClientHello(t, "WWW.3VERGE.COM", tls.VersionTLS13), true, false, false},
		{"wrong SNI", testkit.ClientHello(t, "example.com", tls.VersionTLS13), false, false, false},
		{"subdomain trick", testkit.ClientHello(t, "www.3verge.com.attacker.example", tls.VersionTLS13), false, false, false},
		{"prefix trick", testkit.ClientHello(t, "evilwww.3verge.com", tls.VersionTLS13), false, false, false},
		{"parent domain", testkit.ClientHello(t, "3verge.com", tls.VersionTLS13), false, false, false},
		{"unknown C", testkit.ClientHello(t, "unknown-c.test", tls.VersionTLS13), false, false, false},
		{"no SNI", testkit.ClientHello(t, "", tls.VersionTLS13), false, false, false},
		{"IP has no DNS SNI", testkit.ClientHello(t, "127.0.0.1", tls.VersionTLS13), false, false, false},
		{"malformed SNI", empty, false, false, false},
		{"HTTP", []byte("GET / HTTP/1.1\r\nHost: www.3verge.com\r\n\r\n"), false, false, false},
		{"random TCP", []byte{0x19, 1, 2, 3, 4, 5, 6}, false, false, false},
		{"malformed TLS", malformed, false, false, false},
		{"truncated", valid[:40], false, false, false},
		{"timeout", valid[:2], false, false, true},
		{"oversized record", []byte{22, 3, 1, 0xff, 0xff}, false, false, false},
		{"oversized hello", []byte{22, 3, 1, 0, 4, 1, 0xff, 0xff, 0xff}, false, false, false},
		{"TCP fragmented", valid, true, true, false},
		{"TLS record fragmented", recordFragment, true, false, false},
		{"bytes exactly once", append(append([]byte(nil), valid...), bytes.Repeat([]byte("tail"), 16384)...), true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := count.Load()
			if tc.allow {
				if e := tunnelExchange(endpoint, tc.data, tc.fragment); e != nil {
					t.Fatal(e)
				}
			} else {
				c, e := net.DialTimeout("tcp", tunnelAddress(endpoint), time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(sniff.Timeout + time.Second))
				c.Write(tc.data)
				if !tc.slow {
					c.(*net.TCPConn).CloseWrite()
				}
				var b [1]byte
				n, e := c.Read(b[:])
				var ne net.Error
				if n != 0 || e == nil {
					t.Fatal("blocked input received upstream bytes")
				}
				if errors.As(e, &ne) && ne.Timeout() {
					t.Fatal("guard did not close within its sniff deadline", e)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := m.WaitIdle(ctx); e != nil {
				t.Fatal(e)
			}
			want := before
			if tc.allow {
				want++
			}
			if count.Load() != want {
				t.Fatalf("upstream connections=%d want=%d", count.Load(), want)
			}
		})
	}
	status := m.Status(state, nil)
	if len(status.TunnelGuards) != 1 || status.TunnelGuards[0].Stats.Timeout != 1 || status.TunnelGuards[0].Stats.Allowed == 0 || status.TunnelGuards[0].Stats.Denied == 0 {
		t.Fatal("missing guard observations", status.TunnelGuards)
	}
}

func TestTunnelGuardUnconfiguredAndOtherInbound(t *testing.T) {
	target, count := countedTunnelTarget(t)
	state := tunnelState(t, target, "127.0.0.1")
	other := client.LocalInbound{ID: tunnelID(t), Name: "unrelated socks", Kind: "socks5", Listen: tunnelPort(t, "127.0.0.1")}
	state.LocalInbounds = append(state.LocalInbounds, other)
	m := startTunnel(t, state)
	c, e := net.Dial("tcp", tunnelAddress(other.Listen))
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	defer c.Close()
	if _, e = socks.Handshake(c, socks.Connect, target); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Write([]byte("unrelated")); e != nil {
		t.Fatal(e)
	}
	var b [9]byte
	if _, e = io.ReadFull(c, b[:]); e != nil || string(b[:]) != "unrelated" {
		t.Fatal(e)
	}
	c.Close()
	state.Network.Route.Rules = nil
	r, _ := registry.NewOutbounds()
	p, e := m.Prepare(context.Background(), state, nil, r)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Activate(); e != nil {
		t.Fatal(e)
	}
	before := count.Load()
	hello := testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS13)
	if e = tunnelExchange(state.LocalInbounds[0].Listen, hello, false); e == nil {
		t.Fatal("dormant guard inherited default direct")
	}
	if count.Load() != before {
		t.Fatal("dormant guard dialed")
	}
}

func TestTunnelGuardConcurrentLifecycle(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			target, count := countedTunnelTarget(t)
			state := tunnelState(t, target, host)
			m := startTunnel(t, state)
			hello := testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS13)
			var wg sync.WaitGroup
			errs := make(chan error, 16)
			for range 16 {
				wg.Go(func() { errs <- tunnelExchange(state.LocalInbounds[0].Listen, hello, false) })
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				if e != nil {
					t.Fatal(e)
				}
			}
			if count.Load() != 16 {
				t.Fatal(count.Load())
			}
			c, e := net.Dial("tcp", tunnelAddress(state.LocalInbounds[0].Listen))
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.Write([]byte{22})
			waitTunnelAccepted(t, m, 17)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e = m.Close(ctx); e != nil {
				t.Fatal("shutdown blocked in sniff", e)
			}
			l, e := net.Listen("tcp", tunnelAddress(state.LocalInbounds[0].Listen))
			if e != nil {
				t.Fatal("listener leaked", e)
			}
			l.Close()
		})
	}
}

func waitTunnelAccepted(t *testing.T, m *Manager, want int64) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		gen := m.acquire()
		var accepted int64
		for _, c := range gen.inCounters {
			accepted += c.guard.accepted.Load()
		}
		gen.release()
		if accepted >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("guard did not enter sniffing")
}

func TestTunnelGuardGenerationKeepsConfiguredTarget(t *testing.T) {
	targetA, countA := countedTunnelTarget(t)
	targetB, countB := countedTunnelTarget(t)
	state := tunnelState(t, targetA, "127.0.0.1")
	m := startTunnel(t, state)
	hello := testkit.ClientHello(t, "approved-b.test", tls.VersionTLS13)
	c, err := net.Dial("tcp", tunnelAddress(state.LocalInbounds[0].Listen))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write(hello[:5])
	waitTunnelAccepted(t, m, 1)
	updated := state.Clone()
	updated.LocalInbounds[0].Tunnel.Target = targetB
	r, _ := registry.NewOutbounds()
	p, err := m.Prepare(context.Background(), updated, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Activate(); err != nil {
		t.Fatal(err)
	}
	c.Write(hello[5:])
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, hello) || countA.Load() != 1 || countB.Load() != 0 {
		t.Fatal("in-flight sniff changed target generation", err)
	}
	if err = tunnelExchange(state.LocalInbounds[0].Listen, hello, false); err != nil {
		t.Fatal(err)
	}
	if countA.Load() != 1 || countB.Load() != 1 {
		t.Fatal("new session did not use committed target")
	}
}

type canceledTunnelDialer struct {
	entered  chan access.Endpoint
	canceled chan struct{}
}

func (d *canceledTunnelDialer) DialContext(ctx context.Context, target access.Endpoint) (net.Conn, error) {
	d.entered <- target
	<-ctx.Done()
	close(d.canceled)
	return nil, ctx.Err()
}
func (*canceledTunnelDialer) Close() error { return nil }

func TestTunnelGuardShutdownCancelsUpstreamDial(t *testing.T) {
	state := tunnelState(t, access.Endpoint{Host: "configured-target.test", Port: 443}, "127.0.0.1")
	m := New()
	r, _ := registry.NewOutbounds()
	p, err := m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	d := &canceledTunnelDialer{entered: make(chan access.Endpoint, 1), canceled: make(chan struct{})}
	// Substitute the ordinary native direct adapter before any session exists.
	p.s.outbounds[client.Direct].(*dialerLease).dialer = d
	if err = p.Activate(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close(context.Background()) })
	c, err := net.Dial("tcp", tunnelAddress(state.LocalInbounds[0].Listen))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(testkit.ClientHello(t, "www.3verge.com", tls.VersionTLS13))
	select {
	case got := <-d.entered:
		if got != state.LocalInbounds[0].Tunnel.Target {
			t.Fatal("dial used sniffed SNI", got)
		}
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = m.Close(ctx); err != nil {
		t.Fatal("shutdown did not cancel dial", err)
	}
	select {
	case <-d.canceled:
	default:
		t.Fatal("upstream dial leaked")
	}
}
