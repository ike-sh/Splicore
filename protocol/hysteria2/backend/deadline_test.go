package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestBlockedStreamDeadlineClearChildAndOwnerClose(t *testing.T) {
	for _, mode := range []string{"clear", "child-close", "owner-close"} {
		t.Run(mode, func(t *testing.T) {
			material := testkit.TLS(t)
			pair, e := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
			if e != nil {
				t.Fatal(e)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM([]byte(material.CACertificate))
			q := cfg.QUIC{InitialStreamWindow: 16384, MaxStreamWindow: 16384, InitialConnectionWindow: 32768, MaxConnectionWindow: 32768}
			p, e := net.ListenPacket("udp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			release := make(chan struct{})
			entered := make(chan struct{})
			s, e := NewServer(context.Background(), p, ServerConfig{TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, Transport: cfg.Hysteria{Version: 2, QUIC: q}, Authenticate: func(string) (string, bool) { return "A", true }, TCP: func(ctx context.Context, id string, s *Stream, dst access.Endpoint) error {
				if e := s.Reply(true); e != nil {
					return e
				}
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				_, e := io.Copy(s, s)
				return e
			}, UDP: func(context.Context, string, net.PacketConn) error { return nil }})
			if e != nil {
				t.Fatal(e)
			}
			s.Start()
			defer s.Close(context.Background())
			c, e := NewClient(context.Background(), ClientConfig{TLS: &tls.Config{RootCAs: pool, ServerName: material.ServerName}, Password: "A", Transport: cfg.Hysteria{Version: 2, QUIC: q}, Socket: func(context.Context) (net.PacketConn, net.Addr, error) {
				p, e := net.ListenPacket("udp4", "127.0.0.1:0")
				return p, s.Addr(), e
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			stream, e := c.OpenTCP(context.Background(), access.Endpoint{Host: "localhost", Port: 443})
			if e != nil {
				t.Fatal(e)
			}
			defer stream.Close()
			<-entered
			stream.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, e = stream.Read(make([]byte, 1)); e == nil || !e.(net.Error).Timeout() {
				t.Fatal("blocked read deadline", e)
			}
			stream.SetReadDeadline(time.Time{})
			want := bytes.Repeat([]byte{73, 0, 31, 17}, 16384)
			stream.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
			n, e := stream.Write(want)
			if e == nil || !e.(net.Error).Timeout() || n == len(want) {
				t.Fatal("write was not flow blocked", n, e)
			}
			stream.SetWriteDeadline(time.Time{})
			written := make(chan error, 1)
			go func() {
				_, e := stream.Write(want[n:])
				if e == nil {
					e = stream.(interface{ CloseWrite() error }).CloseWrite()
				}
				written <- e
			}()
			if mode == "clear" {
				close(release)
				stream.SetReadDeadline(time.Now().Add(5 * time.Second))
				got, e := io.ReadAll(stream)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatal("deadline clear truncated stream", e, len(got))
				}
				if e = <-written; e != nil {
					t.Fatal(e)
				}
			} else {
				read := make(chan error, 1)
				go func() { _, e := stream.Read(make([]byte, 1)); read <- e }()
				if mode == "owner-close" {
					c.Close()
				} else {
					stream.Close()
				}
				for _, done := range []chan error{written, read} {
					select {
					case e := <-done:
						if e == nil {
							t.Fatal("blocked IO accepted after close")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("close failed to wake IO")
					}
				}
			}
			c.Close()
			s.Close(context.Background())
			if c.manager.ActiveConnections() != 0 {
				t.Fatal("closed owner retained pool")
			}
		})
	}
}
