package clientruntime

import (
	"context"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/miekg/dns"
)

type heldFlowCloser struct {
	entered, release chan struct{}
	once             sync.Once
}

func (c *heldFlowCloser) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func TestTUNCancellationJoinsConnectionCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New()
		defer m.Close(context.Background())
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := &heldFlowCloser{entered: make(chan struct{}), release: make(chan struct{})}
		join := m.closeFlowOnCancel(ctx, &session{cancel: cancel, packetLocal: c})
		cancel()
		<-c.entered
		done := make(chan struct{})
		go func() { join(); close(done) }()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("generation may retire while cancellation owns connection")
		default:
		}
		close(c.release)
		<-done
	})
}

func tunDNSFixture(t *testing.T, address string) access.Endpoint {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready, done := make(chan struct{}), make(chan error, 1)
	server := &dns.Server{PacketConn: socket, Net: "udp", NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(address)}}
		_ = w.WriteMsg(reply)
	})}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("resolver start")
	}
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return access.Endpoint{Host: "127.0.0.1", Port: uint16(socket.LocalAddr().(*net.UDPAddr).Port)}
}

// The same UDP endpoint must see a DNS profile change on its next request.
// Only the in-flight query retains the old snapshot during reply cleanup.
func TestTUNUDPQueryAcquiresCurrentDNSGeneration(t *testing.T) {
	m := New()
	defer m.Close(context.Background())
	makeGeneration := func(address string) *snapshot {
		id, _ := identity.NewID()
		config := P.Config{Servers: []P.DNSServer{{ID: id, Name: "owned resolver", Type: "udp", Endpoint: tunDNSFixture(t, address), Detour: P.Action{Kind: P.Direct}}}, DNS: P.DNSProfile{Enabled: true, DefaultServer: id, BootstrapServer: id, Strategy: "ipv4_only", TimeoutSeconds: 5, Cache: P.DNSCachePolicy{Capacity: 32}}}
		engine, err := networkruntime.New(config, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		s := &snapshot{network: engine}
		s.refs.Store(1)
		return s
	}
	old := makeGeneration("198.18.0.100")
	next := makeGeneration("198.18.0.101")
	m.current.Store(old)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, peer := net.Pipe()
	defer peer.Close()
	h := &tunIngress{manager: m, ctx: ctx, spec: client.LocalInbound{TUN: &client.TUNSettings{DNSHijack: true}}}
	done := make(chan struct{})
	go func() { defer close(done); defer local.Close(); h.serveDNSPacket(ctx, local) }()
	defer func() { peer.Close(); <-done }()
	query := new(dns.Msg)
	query.SetQuestion("snapshot.owned.test.", dns.TypeA)
	packet, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for index, address := range []string{"198.18.0.100", "198.18.0.101"} {
		if index == 1 {
			m.routeMu.Lock()
			m.current.Store(next)
			m.routeMu.Unlock()
			old.release()
		}
		_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := peer.Write(packet); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, 65535)
		n, err := peer.Read(data)
		if err != nil {
			t.Fatal(err)
		}
		reply := new(dns.Msg)
		if err := reply.Unpack(data[:n]); err != nil {
			t.Fatal(err)
		}
		if len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != address {
			t.Fatal("stale DNS generation", reply.Answer)
		}
	}
}
