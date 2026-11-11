//go:build with_quic

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/quic-go/quic-go"
)

func TestSnellV5RealQUIC(t *testing.T) {
	for _, official := range []bool{false, true} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run(fmt.Sprintf("Official_%t/%s", official, host), func(t *testing.T) {
				ctx, in, h := ownedSnell(t, 5)
				if official {
					_ = h.Close(ctx)
					snellV5Reference(t, in.Inbound.Listeners[0].Endpoint)
				}
				material := testkit.TLSForName(t, "quic.synthetic.test")
				cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AppendCertsFromPEM([]byte(material.CACertificate))
				udp, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				server := &quic.Transport{Conn: udp}
				defer server.Close()
				listener, err := server.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"phase35"}}, &quic.Config{})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				var workers sync.WaitGroup
				defer workers.Wait()
				// Cleanup is ordered before the deferred worker join.
				defer server.Close()
				defer listener.Close()
				workers.Go(func() {
					q, err := listener.Accept(ctx)
					if err != nil {
						return
					}
					defer q.CloseWithError(0, "")
					for {
						s, err := q.AcceptStream(ctx)
						if err != nil {
							return
						}
						workers.Go(func() { _, _ = io.Copy(s, s); _ = s.Close() })
					}
				})
				dst := netaddrEndpoint(udp.LocalAddr())
				d := snellV5Client(t, ctx, in, 5)
				defer d.Close()
				p, err := d.ListenPacket(ctx, dst)
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				client := &quic.Transport{Conn: p}
				defer client.Close()
				admission, cancel := context.WithTimeout(ctx, 8*time.Second)
				defer cancel()
				q, err := client.Dial(admission, netaddr.UDP(dst), &tls.Config{ServerName: "quic.synthetic.test", RootCAs: roots, NextProtos: []string{"phase35"}}, &quic.Config{InitialPacketSize: 1200})
				if err != nil {
					t.Fatal("independent QUIC handshake", err)
				}
				defer q.CloseWithError(0, "")
				var exchanges sync.WaitGroup
				for i := range 8 {
					exchanges.Go(func() {
						s, err := q.OpenStreamSync(admission)
						if err != nil {
							t.Error(err)
							return
						}
						_ = s.SetDeadline(time.Now().Add(8 * time.Second))
						want := bytes.Repeat([]byte{byte(i)}, 256<<10)
						done := make(chan error, 1)
						go func() {
							_, err := s.Write(want)
							if err == nil {
								err = s.Close()
							}
							done <- err
						}()
						got, err := io.ReadAll(s)
						if err != nil || !bytes.Equal(got, want) {
							t.Error("QUIC stream payload", err)
						}
						if err := <-done; err != nil {
							t.Error(err)
						}
					})
				}
				exchanges.Wait()
			})
		}
	}
}
