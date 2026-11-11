//go:build with_quic

package streamtransport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	peer "github.com/apernet/quic-go"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

// A raw alternative accepted QUIC stack is a standards/stream peer. It is not
// an external reference implementation of the Splicore generic wire contract.
func TestPhase31AlternativeQUICPeer(t *testing.T) {
	server, client := nativeTLSFixture(t)
	server.NextProtos = []string{cfg.GenericQUICALPN}
	client.NextProtos = []string{cfg.GenericQUICALPN}
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	rawServer := &peer.Transport{Conn: p}
	defer rawServer.Close()
	listener, e := rawServer.Listen(server, &peer.Config{Versions: []peer.Version{peer.Version1}, MaxIncomingUniStreams: -1})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	cl, e := NewPacketClient(func(context.Context) (net.PacketConn, net.Addr, error) {
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		return p, listener.Addr(), e
	}, cfg.Config{Kind: "quic-stream"}, client)
	if e != nil {
		t.Fatal(e)
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	a, e := cl.DialContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	want := "raw protocol bytes without JLS or target framing"
	if _, e = a.Write([]byte(want)); e != nil {
		t.Fatal(e)
	}
	q, e := listener.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer q.CloseWithError(0, "closed")
	s, e := q.AcceptStream(ctx)
	if e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(want))
	if _, e = io.ReadFull(s, got); e != nil || string(got) != want {
		t.Fatal("wire bytes", string(got), e)
	}
	if _, e = s.Write(got); e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(a, got); e != nil || string(got) != want {
		t.Fatal(e)
	}
	if q.ConnectionState().Version != peer.Version1 || q.ConnectionState().TLS.NegotiatedProtocol != cfg.GenericQUICALPN {
		t.Fatal("negotiation")
	}
}
