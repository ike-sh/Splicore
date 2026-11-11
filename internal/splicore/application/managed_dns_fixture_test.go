package application_test

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/miekg/dns"
	"net"
	"sync/atomic"
	"testing"
)

// Unchanged owned DNS fixture retained for admitted carrier/encryption tests.
func managedDNSFixture(t *testing.T, counter *atomic.Int64) access.Endpoint {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	s := &dns.Server{PacketConn: p, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		counter.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "missing.fixture.local." {
			m.Rcode = dns.RcodeNameError
		} else if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(m)
	})}
	ready, done := make(chan struct{}), make(chan error, 1)
	s.NotifyStartedFunc = func() { close(ready) }
	go func() { done <- s.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		_ = s.Shutdown()
		if e := <-done; e != nil {
			t.Error(e)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(p.LocalAddr().(*net.UDPAddr).Port)}
}
