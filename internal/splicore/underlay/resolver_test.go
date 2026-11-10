package underlay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func resolverWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("resolver worker did not exit")
	}
}

func TestOwnedResolverPendingDialAndLateSocket(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	raw, peer := net.Pipe()
	defer peer.Close()
	r := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		<-release
		return raw, nil
	}}
	owner := ownResolver(r)
	defer owner.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lookupDone := make(chan struct{})
	go func() {
		defer close(lookupDone)
		if _, err := r.LookupNetIP(ctx, "ip4", "owner-lifecycle.invalid."); err == nil {
			t.Error("canceled resolver succeeded")
		}
	}()
	resolverWait(t, entered)
	cancel()
	resolverWait(t, lookupDone)
	closed := make(chan struct{})
	go func() { owner.Close(); close(closed) }()
	// Prove Close sealed admission before checking its pending join.
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, done, err := owner.Begin(context.Background())
		if errors.Is(err, net.ErrClosed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		done()
		if time.Now().After(deadline) {
			t.Fatal("resolver admission not sealed")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("resolver Close returned before physical dial")
	default:
	}
	// Use a separate gate release instead of weakening the cancellation check.
	release <- struct{}{}
	resolverWait(t, closed)
	if _, err := raw.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("late DNS socket not closed", err)
	}
	if _, err := r.Dial(context.Background(), "udp", "127.0.0.1:1"); !errors.Is(err, net.ErrClosed) {
		t.Fatal("late DNS dial admitted", err)
	}
}

type resolverObservedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *resolverObservedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.closed <- struct{}{} })
	return err
}

func TestOwnedResolverClosesActiveQuery(t *testing.T) {
	raw, peer := net.Pipe()
	defer peer.Close()
	query, peerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(peerDone)
		header := make([]byte, 2)
		if _, err := io.ReadFull(peer, header); err != nil {
			return
		}
		body := make([]byte, int(header[0])<<8|int(header[1]))
		if _, err := io.ReadFull(peer, body); err != nil {
			return
		}
		close(query)
		_, _ = io.Copy(io.Discard, peer)
	}()
	r := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) { return raw, nil }}
	owner := ownResolver(r)
	defer owner.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := r.LookupNetIP(ctx, "ip4", "owner-active.invalid."); err == nil {
			t.Error("canceled query succeeded")
		}
	}()
	resolverWait(t, query)
	cancel()
	resolverWait(t, done)
	owner.Close()
	resolverWait(t, peerDone)
}

func TestOwnedResolverUDPAndTCP(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		if !t.Run(network, func(t *testing.T) {
			server := &dns.Server{Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
				answer := new(dns.Msg)
				answer.SetReply(request)
				answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.12")}}
				if err := w.WriteMsg(answer); err != nil {
					t.Error(err)
				}
			})}
			var address string
			var err error
			if network == "udp" {
				server.PacketConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
				if err == nil {
					address = server.PacketConn.LocalAddr().String()
				}
			} else {
				server.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
				if err == nil {
					address = server.Listener.Addr().String()
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			ready, stopped := make(chan struct{}), make(chan struct{})
			server.NotifyStartedFunc = func() { close(ready) }
			go func() {
				defer close(stopped)
				if err := server.ActivateAndServe(); err != nil {
					t.Error(err)
				}
			}()
			defer func() { _ = server.Shutdown(); resolverWait(t, stopped) }()
			resolverWait(t, ready)
			closed := make(chan struct{}, 8)
			var calls atomic.Int64
			r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				calls.Add(1)
				raw, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				conn := &resolverObservedConn{Conn: raw, closed: closed}
				if packet, ok := raw.(net.PacketConn); ok {
					return &resolverPacketConn{Conn: conn, packet: packet}, nil
				}
				return conn, nil
			}}
			owner := ownResolver(r)
			defer owner.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ips, err := r.LookupNetIP(ctx, "ip4", "owner-success.invalid.")
			if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.12" || calls.Load() != 1 {
				t.Fatal("DNS framing/answer changed", ips, err, calls.Load())
			}
			owner.Close()
			resolverWait(t, closed)
		}) {
			return
		}
	}
}
