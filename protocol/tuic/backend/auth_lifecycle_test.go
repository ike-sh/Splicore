package backend

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/protocol/tuic/wire"
	"github.com/quic-go/quic-go"
)

// Authentication has no application response. A real CONNECT round trip proves
// the server accepted the token while FIN is deliberately still outstanding.
// Completing a valid command must not reset the sender before it can send FIN.
func TestAuthenticationCommandDoesNotCancelPendingFIN(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			material := testkit.TLS(t)
			cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM([]byte(material.CACertificate)) {
				t.Fatal("CA")
			}
			packet, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			var uuid [16]byte
			uuid[0] = 1
			target := access.Endpoint{Host: "127.0.0.1", Port: 1234}
			server, err := NewServer(context.Background(), packet, ServerConfig{
				TLS: &tls.Config{Certificates: []tls.Certificate{cert}},
				Authenticate: func(got [16]byte) (User, bool) {
					return User{ID: "test", Password: "synthetic"}, got == uuid
				},
				TCP: func(_ context.Context, _ string, c net.Conn, got access.Endpoint) error {
					if got != target {
						t.Error("CONNECT destination", got)
					}
					_, err := c.Write([]byte("authenticated"))
					return err
				},
			})
			if err != nil {
				packet.Close()
				t.Fatal(err)
			}
			server.Start()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := server.Close(ctx); err != nil {
					t.Error("server cleanup", err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			q, err := quic.DialAddr(ctx, packet.LocalAddr().String(), &tls.Config{RootCAs: roots, ServerName: material.ServerName, NextProtos: []string{"h3"}}, quicConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer q.CloseWithError(0, "")
			state := q.ConnectionState().TLS
			token, err := state.ExportKeyingMaterial(string(uuid[:]), []byte("synthetic"), 32)
			if err != nil {
				t.Fatal(err)
			}
			frame, err := wire.AuthFrame(uuid, token)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := q.OpenUniStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = wire.Write(auth, frame); err != nil {
				t.Fatal(err)
			}
			stream, err := q.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.CancelRead(0)
			defer stream.CancelWrite(0)
			_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
			frame, err = wire.ConnectFrame(target)
			if err != nil {
				t.Fatal(err)
			}
			if err = wire.Write(stream, frame); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(stream)
			if err != nil || string(got) != "authenticated" {
				t.Fatal("server did not authenticate before FIN", string(got), err)
			}
			if cause := context.Cause(auth.Context()); cause != nil {
				t.Fatal("valid authentication stream canceled before FIN", cause)
			}
			if err = auth.Close(); err != nil {
				t.Fatal("authentication FIN", err)
			}
		})
	}
}
