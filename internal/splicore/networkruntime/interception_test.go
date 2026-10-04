package networkruntime

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
)

func TestInterceptedDNSSharedCacheIDsBindingsAndMalformed(t *testing.T) {
	var queries atomic.Int64
	endpoint := dnsFixture(t, "udp", answerHandler(&queries, "198.19.0.1"), nil)
	e, err := New(dnsConfig(endpoint, "udp"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for i, tcp := range []bool{false, true} {
		request := new(dns.Msg)
		request.SetQuestion("Observed.synthetic.test.", dns.TypeA)
		request.Id = uint16(120 + i)
		wire, _ := request.Pack()
		reply, err := e.ExchangeDNS(context.Background(), wire, tcp)
		if err != nil {
			t.Fatal(err)
		}
		response := new(dns.Msg)
		if response.Unpack(reply) != nil || response.Id != request.Id || response.Question[0] != request.Question[0] || response.AuthenticatedData || len(response.Answer) != 1 {
			t.Fatal("reply identity/integrity", response)
		}
	}
	if queries.Load() != 1 || e.ObservedDomain(netip.MustParseAddr("198.19.0.1")) != "observed.synthetic.test" {
		t.Fatal("shared DNS cache/binding", queries.Load())
	}
	before := queries.Load()
	for _, kind := range []string{"short", "response", "multi-question", "extra", "multi-opt", "edns-version"} {
		m := new(dns.Msg)
		m.SetQuestion("invalid.synthetic.test.", dns.TypeA)
		switch kind {
		case "response":
			m.Response = true
		case "multi-question":
			m.Question = append(m.Question, m.Question[0])
		case "extra":
			m.Extra = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "invalid.synthetic.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"x"}}}
		case "multi-opt":
			m.SetEdns0(512, false)
			m.Extra = append(m.Extra, m.Extra[0])
		case "edns-version":
			m.SetEdns0(512, false)
			m.IsEdns0().SetVersion(1)
		}
		b, _ := m.Pack()
		if kind == "short" {
			b = b[:5]
		}
		if _, err = e.ExchangeDNS(context.Background(), b, false); err == nil {
			t.Fatal("malformed accepted", kind)
		}
	}
	if queries.Load() != before {
		t.Fatal("malformed request escaped to resolver")
	}
}

func TestDNSBindingOwnershipExpiryCollisionAndTTL(t *testing.T) {
	e, err := New(dnsConfig(access.Endpoint{Host: "127.0.0.1", Port: 53}, "udp"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ip := netip.MustParseAddr("198.19.0.1")
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "unrelated.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IP(ip.AsSlice())}}
	e.observeDNS("owned.test", m)
	if e.ObservedDomain(ip) != "" {
		t.Fatal("unrelated answer bound")
	}
	m.Answer[0].Header().Name = "owned.test."
	e.observeDNS("owned.test", m)
	if e.ObservedDomain(ip) != "owned.test" {
		t.Fatal("owned answer absent")
	}
	m.Answer[0].Header().Name = "second.test."
	e.observeDNS("second.test", m)
	if e.ObservedDomain(ip) != "" {
		t.Fatal("shared IP guessed")
	}
	e.dnsMu.Lock()
	e.bindings[ip] = dnsBinding{"expired.test", time.Now().Add(-time.Second)}
	e.dnsMu.Unlock()
	if e.ObservedDomain(ip) != "" {
		t.Fatal("expired observation retained")
	}
	c := newDNSCache(2)
	key := dnsKey{domain: "owned.test"}
	m.Answer[0].Header().Ttl = 30
	c.put(key, m, 30)
	entry := c.entries[key].Value.(cacheEntry)
	copy, ok := c.get(key, entry.stored.Add(12*time.Second))
	if !ok || copy.Answer[0].Header().Ttl != 18 || entry.message.Answer[0].Header().Ttl != 30 {
		t.Fatal("cache extends observation lifetime")
	}
}

func FuzzInterceptedDNS(f *testing.F) {
	m := new(dns.Msg)
	m.SetQuestion("fuzz.test.", dns.TypeA)
	b, _ := m.Pack()
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		request, domain, err := decodeInterceptedDNS(b)
		if err == nil {
			if domain == "" || len(request.Question) != 1 {
				t.Fatal("invalid request accepted")
			}
			wire, e := request.Pack()
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = decodeInterceptedDNS(wire); e != nil {
				t.Fatal("parser round trip", e)
			}
		}
	})
}
