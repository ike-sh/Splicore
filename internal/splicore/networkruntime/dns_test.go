package networkruntime

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	P "github.com/sagernet/sing-box/internal/splicore/domain/networkpolicy"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/testkit"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureDialer struct {
	tcp, udp atomic.Int64
	endpoint *access.Endpoint
}

func (d *fixtureDialer) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	d.tcp.Add(1)
	if d.endpoint != nil {
		dst = *d.endpoint
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(dst.Host, fmt.Sprint(dst.Port)))
}
func (d *fixtureDialer) Close() error { return nil }
func (d *fixtureDialer) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	d.udp.Add(1)
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(dst.Host, fmt.Sprint(dst.Port)))
	if err != nil {
		return nil, err
	}
	return &fixturePacket{c}, nil
}

type fixturePacket struct{ net.Conn }

func (c *fixturePacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, e := c.Read(b)
	return n, c.RemoteAddr(), e
}
func (c *fixturePacket) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func dnsFixture(t *testing.T, network string, handler dns.Handler, config *tls.Config) access.Endpoint {
	t.Helper()
	s := &dns.Server{Handler: handler, Net: network}
	var addr net.Addr
	var err error
	if network == "udp" {
		s.PacketConn, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err == nil {
			addr = s.PacketConn.LocalAddr()
		}
	} else {
		s.Listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			addr = s.Listener.Addr()
			if config != nil {
				s.Listener = tls.NewListener(s.Listener, config)
			}
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- s.ActivateAndServe() }()
	select {
	case <-ready:
	case e := <-done:
		t.Fatal(e)
	case <-time.After(5 * time.Second):
		t.Fatal("DNS fixture start")
	}
	t.Cleanup(func() {
		if e := s.Shutdown(); e != nil {
			t.Error(e)
		}
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(addr.(*net.UDPAddr).Port)}
}

// TCP and UDP addresses expose different concrete types.
func dnsTCPFixture(t *testing.T, handler dns.Handler, config *tls.Config) access.Endpoint {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)}
	if config != nil {
		l = tls.NewListener(l, config)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	s := &dns.Server{Listener: l, Net: "tcp", Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := s.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return endpoint
}
func answerHandler(counter *atomic.Int64, ipv4 string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		counter.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "negative.synthetic.test." {
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "synthetic.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 10}, Ns: "ns.synthetic.test.", Mbox: "hostmaster.synthetic.test.", Minttl: 5}}
		} else if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP(ipv4)}}
		} else {
			m.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30}, AAAA: net.ParseIP("::1")}}
		}
		_ = w.WriteMsg(m)
	})
}
func dnsConfig(endpoint access.Endpoint, kind string) P.Config {
	return P.Config{Servers: []P.DNSServer{{ID: testID(1), Name: "resolver", Type: kind, Endpoint: endpoint, Detour: P.Action{Kind: P.Direct}}},
		DNS: P.DNSProfile{Enabled: true, DefaultServer: testID(1), BootstrapServer: testID(1), TimeoutSeconds: 2, Strategy: "ipv4_only", Cache: P.DNSCachePolicy{Capacity: 4}}}
}
func TestDNSUDPAndTCPRuntimeCacheAndNegative(t *testing.T) {
	for _, kind := range []string{"udp", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			var count atomic.Int64
			handler := answerHandler(&count, "127.0.0.1")
			var endpoint access.Endpoint
			if kind == "udp" {
				endpoint = dnsFixture(t, kind, handler, nil)
			} else {
				endpoint = dnsTCPFixture(t, handler, nil)
			}
			e, err := New(dnsConfig(endpoint, kind), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			ctx := context.Background()
			for i := range 2 {
				r, err := e.Lookup(ctx, "UPPER.synthetic.test.")
				if err != nil || r.Addresses[0] != netip.MustParseAddr("127.0.0.1") || r.CacheHit != (i == 1) {
					t.Fatal(r, err)
				}
			}
			if count.Load() != 1 {
				t.Fatal("cache miss", count.Load())
			}
			for range 2 {
				if _, err = e.Lookup(ctx, "negative.synthetic.test"); err == nil {
					t.Fatal("NXDOMAIN succeeded")
				}
			}
			if count.Load() != 2 {
				t.Fatal("negative cache", count.Load())
			}
			e.FlushCache()
			if _, err = e.Lookup(ctx, "upper.synthetic.test"); err != nil {
				t.Fatal(err)
			}
			if count.Load() != 3 {
				t.Fatal("flush", count.Load())
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					for range 5 {
						_, _ = e.Lookup(ctx, "upper.synthetic.test")
						_ = e.DNSStats()
						e.FlushCache()
					}
				})
			}
			wg.Wait()
			if s := e.DNSStats(); s.Entries > s.Capacity || s.Failures != 2 {
				t.Fatal(s)
			}
		})
	}
}
func TestDNSProxyIsolationStrategiesAndSystem(t *testing.T) {
	var direct, proxy atomic.Int64
	a := dnsFixture(t, "udp", answerHandler(&direct, "127.0.0.1"), nil)
	b := dnsTCPFixture(t, answerHandler(&proxy, "127.0.0.2"), nil)
	c := dnsConfig(a, "udp")
	c.Servers = append(c.Servers, P.DNSServer{ID: testID(2), Name: "proxy-resolver", Type: "tcp", Endpoint: b, Detour: P.Action{Kind: P.Group, ID: testID(3)}})
	member := P.Action{Kind: P.Outbound, ID: testID(4)}
	c.Groups = []P.PolicyGroup{{ID: testID(3), Name: "dns-detour", Type: "selector", Members: []P.Action{member}, Selector: &P.SelectorSettings{Selected: member}}}
	c.DNSRules = []P.DNSRule{{ID: testID(5), Name: "split", Match: P.RuleMatch{Suffixes: []string{"proxy.test"}}, Server: testID(2)}}
	d := &fixtureDialer{}
	e, err := New(c, map[identity.ID]ports.ClientDialer{testID(4): d}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	r, err := e.Lookup(context.Background(), "secret.proxy.test")
	if err != nil || r.Server != testID(2) || r.Addresses[0].String() != "127.0.0.2" {
		t.Fatal(r, err)
	}
	if direct.Load() != 0 || proxy.Load() != 1 || d.tcp.Load() != 1 {
		t.Fatal("proxy DNS leak", direct.Load(), proxy.Load(), d.tcp.Load())
	}
	r, err = e.Lookup(context.Background(), "direct.test")
	if err != nil || r.Server != testID(1) || direct.Load() != 1 || proxy.Load() != 1 {
		t.Fatal(r, err)
	}
	for _, strategy := range []string{"dual", "ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6"} {
		cc := dnsConfig(a, "udp")
		cc.DNS.Strategy = strategy
		ee, err := New(cc, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err = ee.Lookup(context.Background(), "strategies.test")
		ee.Close()
		if err != nil {
			t.Fatal(err)
		}
		if strategy == "ipv6_only" || strategy == "prefer_ipv6" {
			if !r.Addresses[0].Is6() {
				t.Fatal(r)
			}
		} else if !r.Addresses[0].Is4() {
			t.Fatal(r)
		}
	}
	sys := dnsConfig(access.Endpoint{}, "system")
	ee, err := New(sys, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ee.Close()
	r, err = ee.Lookup(context.Background(), "localhost")
	if err != nil || len(r.Addresses) == 0 || r.CacheHit {
		t.Fatal(r, err)
	}
}
func TestDNSVerifiedDoT(t *testing.T) {
	material := testkit.TLSForName(t, "dns.synthetic.test")
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int64
	endpoint := dnsTCPFixture(t, answerHandler(&count, "127.0.0.1"), &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	c := dnsConfig(endpoint, "dot")
	c.Servers[0].TLS = access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}
	c.Servers = append(c.Servers, P.DNSServer{ID: testID(2), Name: "bootstrap", Type: "system", Detour: P.Action{Kind: P.Direct}})
	c.DNS.BootstrapServer = testID(2)
	e, err := New(c, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Lookup(context.Background(), "verified.test")
	e.Close()
	if err != nil || len(r.Addresses) != 1 || count.Load() != 1 {
		t.Fatal(r, err)
	}
	for _, change := range []func(*P.Config){func(c *P.Config) { c.Servers[0].TLS.ServerName = "wrong.synthetic.test" }, func(c *P.Config) { c.Servers[0].TLS.Trust = "system"; c.Servers[0].TLS.CACertificate = "" }} {
		cc := c.Clone()
		change(&cc)
		ee, err := New(cc, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ee.Lookup(context.Background(), "verified.test")
		ee.Close()
		if err == nil {
			t.Fatal("invalid TLS trust accepted")
		}
	}
}
func TestCacheTTLIsolationBoundAndFlushGeneration(t *testing.T) {
	c := newDNSCache(2)
	m := new(dns.Msg)
	m.SetQuestion("ttl.test.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "ttl.test.", Rrtype: dns.TypeA, Ttl: 2}, A: net.ParseIP("127.0.0.1")}}
	key := dnsKey{server: testID(1), member: P.Action{Kind: P.Direct}, domain: "ttl.test", strategy: "ipv4_only", kind: dns.TypeA}
	c.put(key, m, dnsTTL(m))
	copy, ok := c.get(key, time.Now())
	if !ok {
		t.Fatal("cache absent")
	}
	copy.Answer[0].Header().Ttl = 0
	if got, _ := c.get(key, time.Now()); got.Answer[0].Header().Ttl != 2 {
		t.Fatal("cache aliases message")
	}
	other := key
	other.server = testID(2)
	if _, hit := c.get(other, time.Now()); hit {
		t.Fatal("server pollution")
	}
	other = key
	other.strategy = "dual"
	if _, hit := c.get(other, time.Now()); hit {
		t.Fatal("strategy pollution")
	}
	other = key
	other.member = P.Action{Kind: P.Outbound, ID: testID(3)}
	if _, hit := c.get(other, time.Now()); hit {
		t.Fatal("member pollution")
	}
	if _, hit := c.get(key, time.Now().Add(3*time.Second)); hit {
		t.Fatal("expired TTL retained")
	}
	for i := range 5 {
		key.domain = fmt.Sprint(i)
		c.put(key, m, 2)
	}
	if len(c.entries) != 2 {
		t.Fatal("unbounded LRU")
	}
	m.Rcode = dns.RcodeServerFailure
	if dnsTTL(m) != 0 {
		t.Fatal("SERVFAIL cached")
	}
}

func TestFlushDoesNotRefillFromInflightQueryAndCloseCancels(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	endpoint := dnsFixture(t, "udp", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		entered <- struct{}{}
		<-release
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("127.0.0.1")}}
		_ = w.WriteMsg(m)
	}), nil)
	e, err := New(dnsConfig(endpoint, "udp"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	done := make(chan error, 1)
	go func() { _, err := e.Lookup(context.Background(), "inflight.test"); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("query never entered fixture")
	}
	e.FlushCache()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.DNSStats().Entries != 0 {
		t.Fatal("pre-flush query refilled cache")
	}
	// An owned query is canceled and joined by Close, even while the resolver is silent.
	silent := dnsFixture(t, "udp", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { entered <- struct{}{} }), nil)
	other, err := New(dnsConfig(silent, "udp"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, err := other.Lookup(context.Background(), "canceled.test"); done <- err }()
	<-entered
	other.Close()
	if err := <-done; err == nil {
		t.Fatal("closed query succeeded")
	}
}
