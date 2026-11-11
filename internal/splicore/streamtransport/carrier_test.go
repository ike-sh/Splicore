package streamtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/streamtransport/mkcp"
)

func TestMKCPCarrierOwnsUDPAndDialAdmission(t *testing.T) {
	m := cfg.DefaultMKCP()
	m.TTI = 10
	settings := cfg.Config{Kind: "mkcp", MKCP: &m}
	l, e := ListenCarrier(context.Background(), "127.0.0.1:0", settings)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	if l.Addr().Network() != "udp" {
		t.Fatal("wrong socket carrier")
	}
	if second, e := ListenCarrier(context.Background(), l.Addr().String(), settings); e == nil {
		second.Close()
		t.Fatal("duplicate UDP bind accepted")
	}
	d := net.Dialer{}
	ctx, cancel := context.WithCancel(context.Background())
	var observed string
	raw, e := Dial(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		observed = network + " " + address
		return d.DialContext(ctx, network, l.Addr().String())
	}, "local.test:12345", settings, nil)
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	cancel()
	c := raw.(*mkcp.Conn)
	defer c.Abort(net.ErrClosed)
	if observed != "udp local.test:12345" {
		t.Fatal("protected dial delegation lost endpoint", observed)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{1})
	server, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	b := make([]byte, 1)
	if _, e = server.Read(b); e != nil || b[0] != 1 {
		t.Fatal("published stream canceled with dial context", e)
	}
}

func TestMKCPFailedTLSJoinsPrivateSocket(t *testing.T) {
	m := cfg.DefaultMKCP()
	m.TTI = 10
	c := cfg.Config{Kind: "mkcp", MKCP: &m}
	l, e := ListenCarrier(context.Background(), "127.0.0.1:0", c)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, e := l.Accept()
		if e != nil {
			return
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		peer.Write([]byte("invalid TLS response"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := net.Dialer{}
	var socket net.Conn
	raw, e := Dial(ctx, func(ctx context.Context, n, a string) (net.Conn, error) {
		var e error
		socket, e = d.DialContext(ctx, n, a)
		return socket, e
	}, l.Addr().String(), c, &tls.Config{ServerName: "invalid.test", MinVersion: tls.VersionTLS12})
	if e == nil {
		raw.Close()
		t.Fatal("invalid TLS accepted")
	}
	if socket == nil {
		t.Fatal("socket missing")
	}
	if _, e = socket.Write([]byte{1}); !errors.Is(e, net.ErrClosed) {
		t.Fatal("failed TLS socket survived", e)
	}
	<-done
}
