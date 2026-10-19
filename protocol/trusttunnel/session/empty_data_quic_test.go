//go:build with_quic

package session

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
	"github.com/quic-go/quic-go/http3"
)

// Use real HTTP/3 DATA frames, including more than the conventional 100 empty
// io.Reader results. Empty DATA is legal and must not truncate a tunnel.
func TestH3EmptyDATAResponseContinuity(t *testing.T) {
	settings := testkit.TLS(t)
	cert, err := os.ReadFile(settings.CertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(settings.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(settings.CACertificate)) {
		t.Fatal("test CA")
	}
	payload := []byte("payload after legal empty H3 DATA\x00")
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if r.Host == "_check" {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		stream := w.(http3.HTTPStreamer).HTTPStream()
		defer stream.Close()
		var response []byte
		switch r.Host {
		case "_udp2":
			d, err := wire.ReadUDP(stream, true)
			if err != nil {
				return
			}
			response, err = wire.EncodeUDP(wire.Datagram{Source: d.Destination, Destination: d.Source, Payload: d.Payload}, false)
			if err != nil {
				return
			}
		case "_icmp":
			var b [23]byte
			if _, err := io.ReadFull(stream, b[:]); err != nil {
				return
			}
			r, err := wire.DecodeEchoRequest(b[:])
			if err != nil {
				return
			}
			response, err = wire.EncodeEchoReply(wire.EchoReply{ID: r.ID, Source: r.Destination, Sequence: r.Sequence})
			if err != nil {
				return
			}
		default:
			response = payload
		}
		for range 128 {
			if _, err := stream.Write(nil); err != nil {
				return
			}
		}
		// Split protocol records across DATA frames, with another empty between.
		if _, err := stream.Write(response[:3]); err != nil {
			return
		}
		if _, err := stream.Write(nil); err != nil {
			return
		}
		if _, err := stream.Write(response[3:]); err != nil {
			return
		}
		if r.Host == "_udp2" || r.Host == "_icmp" {
			_, _ = io.Copy(io.Discard, stream)
		}
	})}
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(packet) }()
	defer func() { _ = server.Close(); _ = packet.Close(); <-served }()
	c := newClient(t, "http3", packet.LocalAddr().String(), &tls.Config{RootCAs: pool, ServerName: settings.ServerName}, nil)
	defer c.Close()
	t.Run("TCP_tail_and_EOF", func(t *testing.T) {
		conn, err := c.Open(context.Background(), "example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("payload=%q err=%v", got, err)
		}
	})
	t.Run("UDP_record", func(t *testing.T) {
		target := netip.MustParseAddrPort("192.0.2.29:53")
		p, err := c.OpenPacket(context.Background(), target)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		_ = p.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = p.WriteTo(payload, net.UDPAddrFromAddrPort(target)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload)+1)
		n, from, err := p.ReadFrom(got)
		if err != nil || from.String() != target.String() || !bytes.Equal(got[:n], payload) {
			t.Fatalf("n=%d from=%v err=%v", n, from, err)
		}
	})
	t.Run("ICMP_record", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		r := wire.EchoRequest{ID: 11, Sequence: 17, Destination: netip.MustParseAddr("192.0.2.29"), TTL: 64, DataSize: 32}
		got, err := c.Echo(ctx, r)
		if err != nil || got.ID != r.ID || got.Sequence != r.Sequence || got.Source != r.Destination {
			t.Fatalf("reply=%+v err=%v", got, err)
		}
	})
}

func TestH3EmptyDATARequestContinuity(t *testing.T) {
	a, tc, _ := startServer(t, "http3", nil)
	c := newClient(t, "http3", a, tc, nil)
	defer c.Close()
	owner, err := c.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target := tcpEcho(t, "tcp4", "127.0.0.1:0")
	s, err := owner.raw.(*h3Connection).client.OpenRequestStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.CancelRead(0x10c)
	defer s.CancelWrite(0x10c)
	_ = s.SetDeadline(time.Now().Add(3 * time.Second))
	if err = s.SendRequestHeader(&http.Request{Method: http.MethodConnect, URL: &url.URL{Scheme: "https", Host: target}, Host: target, Header: c.headers(target), ContentLength: -1}); err != nil {
		t.Fatal(err)
	}
	r, err := s.ReadResponse()
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("response=%v err=%v", r, err)
	}
	for range 128 {
		if _, err = s.Write(nil); err != nil {
			t.Fatal(err)
		}
	}
	payload := bytes.Repeat([]byte("upload tail\x00"), 512)
	if _, err = s.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("got=%d expected=%d err=%v", len(got), len(payload), err)
	}
}
