package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	ht "github.com/ike-sh/Splicore/internal/splicore/streamtransport/hysteria"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

func TestQUICDatagramSelectedFragmentLossAndLiveExpiry(t *testing.T) {
	material := testkit.TLS(t)
	pair, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(material.CACertificate))
	packet, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var admitted, active, delivered atomic.Int64
	peers := make(chan *peer, 1)
	s, e := ht.NewServer(context.Background(), packet, ht.ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, Settings: cfg.Hysteria{Version: 2, UDPIdleTimeout: 2}, Authenticate: func(string) (string, bool) { return "A", true }, Application: func(c *ht.Connection) ht.Hooks {
		p := &peer{connection: c, packets: map[uint32]*session{}, config: ServerConfig{Transport: cfg.Hysteria{Version: 2, UDPIdleTimeout: 2}, UDP: func(ctx context.Context, id string, p net.PacketConn) error {
			admitted.Add(1)
			active.Add(1)
			defer active.Add(-1)
			b := make([]byte, 4096)
			for {
				n, a, e := p.ReadFrom(b)
				if e != nil {
					return e
				}
				delivered.Add(1)
				if _, e = p.WriteTo(b[:n], a); e != nil {
					return e
				}
			}
		}}}
		peers <- p
		return ht.Hooks{Admitted: func() { c.Go(p.receive) }}
	}})
	if e != nil {
		t.Fatal(e)
	}
	s.Start()
	defer s.Close(context.Background())
	c, e := NewClient(context.Background(), ClientConfig{TLS: &tls.Config{RootCAs: pool, ServerName: material.ServerName}, Password: "A", Socket: func(context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		return p, packet.LocalAddr(), e
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	dst := access.Endpoint{Host: "localhost", Port: 443}
	p, e := c.OpenPacket(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	carrier, e := c.manager.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	server := <-peers
	inner := p.(*DefaultPacket).PacketConn.(*Packet)
	want := bytes.Repeat([]byte{73, 0, 17, 31}, 1024)
	parts, e := wire.FragmentsAt(inner.session, 500, dst, want, 900)
	if e != nil || len(parts) < 3 {
		t.Fatal(e)
	}
	// The impairment drops exactly encoded fragment 1 at QUIC DATAGRAM
	// admission. All survivors traverse actual QUIC; they are sent in reverse.
	for i := len(parts) - 1; i >= 0; i-- {
		if i == 1 {
			continue
		}
		if e := carrier.SendDatagram(context.Background(), parts[i]); e != nil {
			t.Fatal(e)
		}
	}
	wait := func(want int64) {
		t.Helper()
		deadline := time.NewTimer(7 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for server.partial.Load() != want {
			select {
			case <-tick.C:
			case <-deadline.C:
				t.Fatal("fragment state", server.partial.Load(), want)
			}
		}
	}
	wait(1)
	p.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, _, e := p.ReadFrom(make([]byte, 4096)); e == nil {
		t.Fatal("incomplete UDP delivered")
	}
	if admitted.Load() != 0 || delivered.Load() != 0 {
		t.Fatal("partial admitted target")
	}
	wait(0)
	p.SetDeadline(time.Now().Add(5 * time.Second))
	if _, e = p.WriteTo(want, nil); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 4096)
	n, _, e := p.ReadFrom(got)
	if e != nil || !bytes.Equal(want, got[:n]) {
		t.Fatal("later packet poisoned", e)
	}
	if delivered.Load() != 1 || admitted.Load() != 1 {
		t.Fatal("unexpected retransmission/delivery", delivered.Load(), admitted.Load())
	}
	c.Close()
	s.Close(context.Background())
	if server.partial.Load() != 0 || active.Load() != 0 || c.manager.ActiveConnections() != 0 {
		t.Fatal("fragment owner baseline")
	}
}
