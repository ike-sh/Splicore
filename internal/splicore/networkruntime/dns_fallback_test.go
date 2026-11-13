package networkruntime

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/miekg/dns"
)

func TestProtectedDNSUDPTruncationFallsBackToTCP(t *testing.T) {
	var tcpQueries, udpQueries atomic.Int64
	endpoint := dnsFallbackPairFixture(t, answerHandler(&tcpQueries, "192.0.2.42"), dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	}))
	x := testkit.NewUnderlay(t)
	lease, err := x.Factory.Begin(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	e, err := NewWithUnderlay(x.Factory, lease.ID, dnsConfig(endpoint, "udp"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	result, err := e.Lookup(context.Background(), "answer.fixture.invalid")
	if err != nil || len(result.Addresses) != 1 || result.Addresses[0].String() != "192.0.2.42" {
		t.Fatal(result, err)
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Fatal("fallback repeated a query", udpQueries.Load(), tcpQueries.Load())
	}
	// Both sockets must pass through the owned protection boundary.
	if x.Backend.Count(underlay.DNSUpstream) != 2 {
		t.Fatal("fallback socket bypassed protection", x.Backend.SnapshotEvents())
	}
}
