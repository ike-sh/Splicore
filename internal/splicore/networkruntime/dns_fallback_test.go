package networkruntime

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/miekg/dns"
)

func TestProtectedDNSUDPTruncationFallsBackToTCP(t *testing.T) {
	var tcpQueries, udpQueries atomic.Int64
	endpoint := dnsTCPFixture(t, answerHandler(&tcpQueries, "192.0.2.42"), nil)
	pc, err := net.ListenPacket("udp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	peer := &dns.Server{PacketConn: pc, Net: "udp", NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	go func() { done <- peer.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := peer.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
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
