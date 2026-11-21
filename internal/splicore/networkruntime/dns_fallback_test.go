package networkruntime

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/miekg/dns"
)

type dnsFallbackReply struct {
	id        uint16
	truncated bool
	rcode     int
	answers   int
	writeErr  error
}

func recordDNSFallbackReply(reply *atomic.Pointer[dnsFallbackReply], message *dns.Msg, err error) {
	reply.Store(&dnsFallbackReply{message.Id, message.Truncated, message.Rcode, len(message.Answer), err})
}

type dnsFallbackWriter struct {
	dns.ResponseWriter
	reply *atomic.Pointer[dnsFallbackReply]
}

func (w dnsFallbackWriter) WriteMsg(message *dns.Msg) error {
	err := w.ResponseWriter.WriteMsg(message)
	recordDNSFallbackReply(w.reply, message, err)
	return err
}

func dnsFallbackError(err error) (string, syscall.Errno) {
	if err == nil {
		return "ok", 0
	}
	var errno syscall.Errno
	_ = errors.As(err, &errno)
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout", errno
	}
	if errno != 0 {
		return "socket_error", errno
	}
	return "error", 0
}

func TestProtectedDNSUDPTruncationFallsBackToTCP(t *testing.T) {
	var tcpQueries, udpQueries atomic.Int64
	var udpReply, tcpReply atomic.Pointer[dnsFallbackReply]
	var fixture *testkit.UnderlayFixture
	// Run after shutdown has joined both servers. Keep only fixture metadata.
	t.Cleanup(func() {
		protection := 0
		fallback := "unobserved"
		if fixture != nil {
			protection = fixture.Backend.Count(underlay.DNSUpstream)
			for _, event := range fixture.Backend.SnapshotEvents() {
				if event.Scope.Purpose == underlay.DNSUpstream && strings.HasPrefix(event.Network, "tcp") {
					fallback = "tcp_protect"
				}
			}
		}
		udp, tcp := udpReply.Load(), tcpReply.Load()
		if udp != nil && tcp != nil && udp.truncated && udp.writeErr == nil && udp.id == tcp.id {
			fallback = "matching_tcp_reply"
		}
		t.Logf("dns_fallback_counts udp=%d tcp=%d protection=%d fallback=%s", udpQueries.Load(), tcpQueries.Load(), protection, fallback)
		for _, item := range []struct {
			network string
			reply   *dnsFallbackReply
		}{{"udp", udp}, {"tcp", tcp}} {
			if item.reply != nil {
				reply := item.reply
				result, errno := dnsFallbackError(reply.writeErr)
				t.Logf("dns_fallback_reply network=%s id=%d tc=%t rcode=%d answers=%d result=%s errno=%d",
					item.network, reply.id, reply.truncated, reply.rcode, reply.answers, result, errno)
			}
		}
	})
	observe := func(stage string, port uint16, err error) {
		result, errno := dnsFallbackError(err)
		t.Logf("dns_fallback_stage stage=%s port=%d result=%s errno=%d", stage, port, result, errno)
	}
	answer := answerHandler(&tcpQueries, "192.0.2.42")
	endpoint := dnsTCPFixtureObserved(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		answer.ServeDNS(dnsFallbackWriter{w, &tcpReply}, req)
	}), nil, observe)
	pc, err := net.ListenPacket("udp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
	observe("udp_bind", endpoint.Port, err)
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	peer := &dns.Server{PacketConn: pc, Net: "udp", NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		recordDNSFallbackReply(&udpReply, m, w.WriteMsg(m))
	})}
	go func() { done <- peer.ActivateAndServe() }()
	<-ready
	observe("udp_ready", endpoint.Port, nil)
	t.Cleanup(func() {
		shutdown, served := peer.Shutdown(), <-done
		observe("udp_shutdown", endpoint.Port, shutdown)
		observe("udp_serve", endpoint.Port, served)
		if shutdown != nil {
			t.Error(shutdown)
		}
		if served != nil {
			t.Error(served)
		}
	})
	x := testkit.NewUnderlay(t)
	fixture = x
	lease, err := x.Factory.Begin(context.Background(), true)
	observe("underlay_begin", endpoint.Port, err)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	e, err := NewWithUnderlay(x.Factory, lease.ID, dnsConfig(endpoint, "udp"), nil, nil)
	observe("engine_start", endpoint.Port, err)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	result, err := e.Lookup(context.Background(), "answer.fixture.invalid")
	observe("lookup", endpoint.Port, err)
	matched := len(result.Addresses) == 1 && result.Addresses[0].String() == "192.0.2.42"
	t.Logf("dns_fallback_answer addresses=%d matched=%t", len(result.Addresses), matched)
	if err != nil || !matched {
		t.Log("dns_fallback_assertion check=answer")
		t.Fatal(result, err)
	}
	if udpQueries.Load() != 1 || tcpQueries.Load() != 1 {
		t.Log("dns_fallback_assertion check=counts")
		t.Fatal("fallback repeated a query", udpQueries.Load(), tcpQueries.Load())
	}
	// Both sockets must pass through the owned protection boundary.
	if x.Backend.Count(underlay.DNSUpstream) != 2 {
		t.Log("dns_fallback_assertion check=protection")
		t.Fatal("fallback socket bypassed protection", x.Backend.SnapshotEvents())
	}
}
