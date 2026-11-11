package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedStreamsAndDatagramSessions(t *testing.T) {
	material := testkit.TLS(t)
	pair, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(material.CACertificate))
	packet, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	var sessions atomic.Int64
	server, e := NewServer(context.Background(), packet, ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, Transport: cfg.Hysteria{Version: 2, UDPIdleTimeout: 2}, Authenticate: func(s string) (string, bool) { return s, s == "A" }, TCP: func(ctx context.Context, id string, s *Stream, dst access.Endpoint) error {
		if id != "A" {
			t.Error("identity")
		}
		if dst.Port == 1 {
			return wire.ErrRejected
		}
		if e := s.Reply(true); e != nil {
			return e
		}
		_, e := io.Copy(s, s)
		return e
	}, UDP: func(ctx context.Context, id string, p net.PacketConn) error {
		sessions.Add(1)
		defer sessions.Add(-1)
		b := make([]byte, wire.MaxUDP)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return e
			}
			if _, e = p.WriteTo(b[:n], a); e != nil {
				return e
			}
		}
	}})
	if e != nil {
		t.Fatal(e)
	}
	server.Start()
	defer server.Close(context.Background())
	var sockets atomic.Int64
	client, e := NewClient(context.Background(), ClientConfig{TLS: &tls.Config{RootCAs: pool, ServerName: material.ServerName}, Password: "A", Socket: func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		sockets.Add(1)
		return p, packet.LocalAddr(), e
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	dst := access.Endpoint{Host: "127.0.0.1", Port: 443}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			c, e := client.OpenTCP(context.Background(), dst)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{byte(i), 0, 31}, (1<<20)/3+1)
			written := make(chan error, 1)
			go func() {
				for start := 0; start < len(payload); {
					end := min(start+701, len(payload))
					_, e := c.Write(payload[start:end])
					if e != nil {
						written <- e
						return
					}
					start = end
				}
				written <- c.(interface{ CloseWrite() error }).CloseWrite()
			}()
			got, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(got, payload) {
				t.Error("multiplex/EOF integrity", e)
			}
			if e = <-written; e != nil {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	if sockets.Load() != 1 {
		t.Fatal("TCP did not reuse connection", sockets.Load())
	}
	if c, e := client.OpenTCP(context.Background(), access.Endpoint{Host: "127.0.0.1", Port: 1}); e == nil {
		c.Close()
		t.Fatal("target failure accepted")
	}
	a, _ := client.OpenPacket(context.Background(), dst)
	b, _ := client.OpenPacket(context.Background(), dst)
	defer a.Close()
	defer b.Close()
	check := func(p net.PacketConn, size int) {
		t.Helper()
		p.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte{byte(size), 17}, (size+1)/2)[:size]
		if _, e := p.WriteTo(payload, nil); e != nil {
			t.Fatal(e)
		}
		buffer := make([]byte, wire.MaxUDP)
		n, _, e := p.ReadFrom(buffer)
		if e != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatal("UDP integrity", e)
		}
	}
	for _, size := range []int{1, 1000, 4096, 2048} {
		check(a, size)
		check(b, size)
	}
	a.Close()
	check(b, 4096)
	if sockets.Load() != 1 {
		t.Fatal("UDP did not share TCP carrier")
	}
	for range 256 {
		p, e := client.OpenPacket(context.Background(), dst)
		if e != nil {
			t.Fatal(e)
		}
		p.Close()
	}
	if c, e := client.OpenTCP(context.Background(), dst); e != nil {
		t.Fatal("sibling after failed target", e)
	} else {
		c.Close()
	}
	client.Close()
	server.Close(context.Background())
	if sessions.Load() != 0 || client.manager.ActiveConnections() != 0 {
		t.Fatal("parent cleanup retained session")
	}
}
func TestSessionClockExpiryReleasesAndRecreates(t *testing.T) {
	now := time.Unix(123, 0)
	var released atomic.Int64
	p := &peer{config: ServerConfig{Transport: cfg.Hysteria{Version: 2, UDPIdleTimeout: 60}}, packets: map[uint32]*session{}}
	for i := range 256 {
		packet := newPacket(context.Background(), nil, 77, func(context.Context, []byte) error { return nil })
		packet.afterClose = func() { released.Add(1) }
		p.packets[77] = &session{packet: packet, last: now}
		if len(p.expire(now.Add(59*time.Second))) != 0 {
			t.Fatal("early expiry")
		}
		if len(p.expire(now.Add(60*time.Second))) != 1 || len(p.packets) != 0 || packet.ctx.Err() == nil {
			t.Fatal("idle retention")
		}
		packet.Close()
		if released.Load() != int64(i+1) {
			t.Fatal("release not exactly once")
		}
		now = now.Add(time.Minute)
	}
}
