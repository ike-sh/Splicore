package networkruntime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/miekg/dns"
)

const dnsFallbackBindAttempts = 8

type dnsFallbackBinder struct {
	listenTCP func() (net.Listener, error)
	listenUDP func(port uint16) (net.PacketConn, error)
}

type dnsFallbackSocketPair struct {
	listener net.Listener
	packet   net.PacketConn
	endpoint access.Endpoint
}

func networkDNSFallbackBinder(host string) dnsFallbackBinder {
	return dnsFallbackBinder{
		listenTCP: func() (net.Listener, error) {
			return net.Listen("tcp", net.JoinHostPort(host, "0"))
		},
		listenUDP: func(port uint16) (net.PacketConn, error) {
			return net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
		},
	}
}

func bindDNSFallbackSocketPair(host string, binder dnsFallbackBinder, attempts int, observe func(string, uint16, error)) (*dnsFallbackSocketPair, error) {
	if attempts <= 0 {
		return nil, errors.New("DNS fallback fixture bind attempts must be positive")
	}
	if binder.listenTCP == nil || binder.listenUDP == nil {
		return nil, errors.New("DNS fallback fixture binder is incomplete")
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		listener, err := binder.listenTCP()
		if err == nil && listener == nil {
			err = errors.New("TCP binder returned a nil listener")
		}
		if err != nil {
			if observe != nil {
				observe("tcp_bind", 0, err)
			}
			lastErr = fmt.Errorf("TCP bind attempt %d: %w", attempt, err)
			continue
		}
		tcpAddress, ok := listener.Addr().(*net.TCPAddr)
		if !ok || tcpAddress.Port <= 0 || tcpAddress.Port > 65535 {
			err = fmt.Errorf("TCP bind attempt %d returned invalid address %T %v", attempt, listener.Addr(), listener.Addr())
			if observe != nil {
				observe("tcp_bind", 0, err)
			}
			closeErr := listener.Close()
			if observe != nil {
				observe("tcp_retry_close", 0, closeErr)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("release invalid TCP listener: %w", errors.Join(err, closeErr))
			}
			lastErr = err
			continue
		}
		port := uint16(tcpAddress.Port)
		if observe != nil {
			observe("tcp_bind", port, nil)
		}
		packet, packetErr := binder.listenUDP(port)
		if packetErr == nil && packet == nil {
			packetErr = errors.New("UDP binder returned a nil packet connection")
		}
		if observe != nil {
			observe("udp_bind", port, packetErr)
		}
		if packetErr == nil {
			return &dnsFallbackSocketPair{
				listener: listener,
				packet:   packet,
				endpoint: access.Endpoint{Host: host, Port: port},
			}, nil
		}
		closeErr := listener.Close()
		if observe != nil {
			observe("tcp_retry_close", port, closeErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("release TCP listener after UDP bind attempt %d: %w", attempt, errors.Join(packetErr, closeErr))
		}
		lastErr = fmt.Errorf("UDP bind attempt %d on port %d: %w", attempt, port, packetErr)
	}
	return nil, fmt.Errorf("acquire TCP/UDP DNS fallback fixture after %d attempts: %w", attempts, lastErr)
}

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
	pair, err := bindDNSFallbackSocketPair("127.0.0.1", networkDNSFallbackBinder("127.0.0.1"), dnsFallbackBindAttempts, observe)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := pair.endpoint
	tcpReady, tcpDone := make(chan struct{}), make(chan error, 1)
	tcpPeer := &dns.Server{
		Listener:          pair.listener,
		Net:               "tcp",
		NotifyStartedFunc: func() { close(tcpReady) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			answer.ServeDNS(dnsFallbackWriter{w, &tcpReply}, req)
		}),
	}
	go func() { tcpDone <- tcpPeer.ActivateAndServe() }()
	<-tcpReady
	observe("tcp_ready", endpoint.Port, nil)
	t.Cleanup(func() {
		shutdown, served := tcpPeer.Shutdown(), <-tcpDone
		observe("tcp_shutdown", endpoint.Port, shutdown)
		observe("tcp_serve", endpoint.Port, served)
		if shutdown != nil {
			t.Error(shutdown)
		}
		if served != nil {
			t.Error(served)
		}
	})
	udpReady, udpDone := make(chan struct{}), make(chan error, 1)
	udpPeer := &dns.Server{PacketConn: pair.packet, Net: "udp", NotifyStartedFunc: func() { close(udpReady) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		udpQueries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		recordDNSFallbackReply(&udpReply, m, w.WriteMsg(m))
	})}
	go func() { udpDone <- udpPeer.ActivateAndServe() }()
	<-udpReady
	observe("udp_ready", endpoint.Port, nil)
	t.Cleanup(func() {
		shutdown, served := udpPeer.Shutdown(), <-udpDone
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

type dnsFallbackTrackingListener struct {
	address  *net.TCPAddr
	closed   atomic.Bool
	closeErr error
}

func (l *dnsFallbackTrackingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *dnsFallbackTrackingListener) Addr() net.Addr            { return l.address }
func (l *dnsFallbackTrackingListener) Close() error {
	l.closed.Store(true)
	return l.closeErr
}

type dnsFallbackTrackingPacketConn struct {
	address *net.UDPAddr
	closed  atomic.Bool
}

func (c *dnsFallbackTrackingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *dnsFallbackTrackingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, net.ErrClosed
}
func (c *dnsFallbackTrackingPacketConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *dnsFallbackTrackingPacketConn) LocalAddr() net.Addr              { return c.address }
func (c *dnsFallbackTrackingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *dnsFallbackTrackingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *dnsFallbackTrackingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type dnsFallbackBindObservation struct {
	stage string
	port  uint16
	err   error
}

func TestDNSFallbackSocketPairRetriesAfterUDPBindFailure(t *testing.T) {
	bindErr := &net.OpError{Op: "listen", Net: "udp", Err: syscall.EACCES}
	var listeners []*dnsFallbackTrackingListener
	var packet *dnsFallbackTrackingPacketConn
	udpCalls := 0
	binder := dnsFallbackBinder{
		listenTCP: func() (net.Listener, error) {
			listener := &dnsFallbackTrackingListener{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001 + len(listeners)}}
			listeners = append(listeners, listener)
			return listener, nil
		},
		listenUDP: func(port uint16) (net.PacketConn, error) {
			udpCalls++
			if udpCalls == 1 {
				return nil, bindErr
			}
			packet = &dnsFallbackTrackingPacketConn{address: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}}
			return packet, nil
		},
	}
	var observations []dnsFallbackBindObservation
	pair, err := bindDNSFallbackSocketPair("127.0.0.1", binder, 3, func(stage string, port uint16, err error) {
		observations = append(observations, dnsFallbackBindObservation{stage, port, err})
	})
	if err != nil {
		t.Fatal(err)
	}
	if udpCalls != 2 || len(listeners) != 2 {
		t.Fatalf("unexpected attempts: tcp=%d udp=%d", len(listeners), udpCalls)
	}
	if pair.endpoint != (access.Endpoint{Host: "127.0.0.1", Port: 41002}) {
		t.Fatalf("unexpected endpoint: %+v", pair.endpoint)
	}
	if !listeners[0].closed.Load() {
		t.Fatal("first TCP listener remained open after the injected UDP bind failure")
	}
	if listeners[1].closed.Load() || packet == nil || packet.closed.Load() {
		t.Fatal("successful TCP/UDP pair was closed before fixture ownership transfer")
	}
	wantStages := []string{"tcp_bind", "udp_bind", "tcp_retry_close", "tcp_bind", "udp_bind"}
	wantPorts := []uint16{41001, 41001, 41001, 41002, 41002}
	if len(observations) != len(wantStages) {
		t.Fatalf("unexpected observation count: got=%d want=%d", len(observations), len(wantStages))
	}
	for i, observation := range observations {
		if observation.stage != wantStages[i] || observation.port != wantPorts[i] {
			t.Fatalf("observation %d: got=%+v want_stage=%s want_port=%d", i, observation, wantStages[i], wantPorts[i])
		}
	}
	if !errors.Is(observations[1].err, syscall.EACCES) || observations[2].err != nil {
		t.Fatalf("retry diagnostics lost bind or close result: bind=%v close=%v", observations[1].err, observations[2].err)
	}
	if err := errors.Join(pair.packet.Close(), pair.listener.Close()); err != nil {
		t.Fatal(err)
	}
	if !listeners[1].closed.Load() || !packet.closed.Load() {
		t.Fatal("successful TCP/UDP pair did not release both resources")
	}
}

func TestDNSFallbackSocketPairExhaustionPreservesBindError(t *testing.T) {
	bindErr := &net.OpError{Op: "listen", Net: "udp", Err: syscall.EACCES}
	var listeners []*dnsFallbackTrackingListener
	udpCalls := 0
	binder := dnsFallbackBinder{
		listenTCP: func() (net.Listener, error) {
			listener := &dnsFallbackTrackingListener{address: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 42001 + len(listeners)}}
			listeners = append(listeners, listener)
			return listener, nil
		},
		listenUDP: func(uint16) (net.PacketConn, error) {
			udpCalls++
			return nil, bindErr
		},
	}
	var observations []dnsFallbackBindObservation
	pair, err := bindDNSFallbackSocketPair("127.0.0.1", binder, 3, func(stage string, port uint16, err error) {
		observations = append(observations, dnsFallbackBindObservation{stage, port, err})
	})
	if pair != nil {
		t.Fatal("exhausted binder returned a socket pair")
	}
	if err == nil || !errors.Is(err, syscall.EACCES) || !strings.Contains(err.Error(), "after 3 attempts") {
		t.Fatalf("exhaustion did not preserve the bounded bind failure: %v", err)
	}
	if udpCalls != 3 || len(listeners) != 3 {
		t.Fatalf("unexpected attempts: tcp=%d udp=%d", len(listeners), udpCalls)
	}
	for i, listener := range listeners {
		if !listener.closed.Load() {
			t.Fatalf("TCP listener %d remained open after UDP bind failure", i)
		}
	}
	retryCloses := 0
	for _, observation := range observations {
		if observation.stage == "tcp_retry_close" {
			retryCloses++
			if observation.err != nil {
				t.Fatalf("retry close failed: %v", observation.err)
			}
		}
	}
	if retryCloses != 3 {
		t.Fatalf("unexpected retry close observations: got=%d want=3", retryCloses)
	}
}
