package backend

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/quic-go/quic-go"
)

func packetStreamPair(t *testing.T) (*quic.Conn, *quic.Conn) {
	t.Helper()
	material := testkit.TLS(t)
	cert, err := tls.LoadX509KeyPair(material.CertificateFile, material.PrivateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(material.CACertificate)) {
		t.Fatal("CA")
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{RootCAs: pool, ServerName: material.ServerName, NextProtos: []string{"h3"}}, &quic.Config{MaxIncomingUniStreams: 1, InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	return server, client
}

func TestPacketStreamAssociationCancellationAndSibling(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "parent"} {
		t.Run(mode, func(t *testing.T) {
			server, client := packetStreamPair(t)
			q := packetio.New(server.Context(), server.LocalAddr(), func(ctx context.Context, b []byte, _ net.Addr) error { return sendPacketStream(ctx, server, b) })
			defer q.Close()
			result := make(chan error, 1)
			go func() { _, err := q.WriteTo(bytes.Repeat([]byte{1}, 65536), nil); result <- err }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			blocked, err := client.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Peer window is 1 KiB and never read, so the 64 KiB write cannot finish.
			switch mode {
			case "close":
				_ = q.Close()
			case "deadline":
				_ = q.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			case "parent":
				_ = client.CloseWithError(0, "")
			}
			select {
			case err := <-result:
				want := net.ErrClosed
				if mode == "deadline" {
					want = os.ErrDeadlineExceeded
				}
				if !errors.Is(err, want) {
					t.Fatalf("%v want %v", err, want)
				}
			case <-ctx.Done():
				t.Fatal("stream cancellation stalled")
			}
			if mode == "parent" {
				return
			}
			blocked.CancelRead(0)
			go func() { result <- sendPacketStream(ctx, server, []byte("sibling")) }()
			sibling, err := client.AcceptUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(sibling)
			if err != nil || string(got) != "sibling" {
				t.Fatalf("%q %v", got, err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPacketStreamAdmissionDeadline(t *testing.T) {
	server, client := packetStreamPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held, err := server.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = held.Write([]byte("hold")); err != nil {
		t.Fatal(err)
	}
	read, err := client.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer read.CancelRead(0)
	defer held.CancelWrite(0)
	q := packetio.New(server.Context(), server.LocalAddr(), func(ctx context.Context, b []byte, _ net.Addr) error { return sendPacketStream(ctx, server, b) })
	defer q.Close()
	_ = q.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := q.WriteTo([]byte("no-stream-credit"), nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
}
