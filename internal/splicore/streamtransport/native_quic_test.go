//go:build with_quic

package streamtransport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
)

func quicFixture(t *testing.T) (*Client, net.Listener, *atomic.Int32) {
	t.Helper()
	server, client := nativeTLSFixture(t)
	c := cfg.Config{Kind: "quic-stream"}
	base, e := ListenCarrier(t.Context(), "127.0.0.1:0", c)
	if e != nil {
		t.Fatal(e)
	}
	l, e := WrapListener(base, c, server)
	if e != nil {
		base.Close()
		t.Fatal(e)
	}
	count := &atomic.Int32{}
	cl, e := NewPacketClient(func(context.Context) (net.PacketConn, net.Addr, error) {
		count.Add(1)
		p, e := net.ListenPacket("udp4", "127.0.0.1:0")
		return p, l.Addr(), e
	}, c, client)
	if e != nil {
		l.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { cl.Close(); l.Close() })
	return cl, l, count
}

func TestPhase31QUICDuplexAndHalfClose(t *testing.T) {
	cl, l, count := quicFixture(t)
	for _, n := range []int{1, 16384, 256 << 10, 2 << 20} {
		nativeEcho(t, cl, l, bytes.Repeat([]byte{byte(n)}, n))
	}
	if count.Load() != 1 {
		t.Fatal("session not reused", count.Load())
	}
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = a.Write([]byte("preface-free")); e != nil {
		t.Fatal(e)
	}
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(3 * time.Second))
	if e = a.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(b)
	if e != nil || string(got) != "preface-free" {
		t.Fatal(string(got), e)
	}
	if _, e = b.Write([]byte("after EOF")); e != nil {
		t.Fatal(e)
	}
	if e = b.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e = io.ReadAll(a)
	if e != nil || string(got) != "after EOF" {
		t.Fatal(string(got), e)
	}
}

func TestPhase31QUICConcurrentIsolation(t *testing.T) {
	cl, l, count := quicFixture(t)
	const n = 20
	streams := make([]net.Conn, 0, n)
	for i := range n {
		a, e := cl.DialContext(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		a.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e = a.Write([]byte{byte(i)}); e != nil {
			t.Fatal(e)
		}
		streams = append(streams, a)
	}
	for range n {
		b, e := l.Accept()
		if e != nil {
			t.Fatal(e)
		}
		go func() {
			defer b.Close()
			v := make([]byte, 1)
			if _, e := io.ReadFull(b, v); e == nil {
				b.Write(v)
			}
		}()
	}
	for i, a := range streams {
		v := make([]byte, 1)
		if _, e := io.ReadFull(a, v); e != nil || v[0] != byte(i) {
			t.Fatal(i, v, e)
		}
		a.Close()
	}
	if count.Load() != 1 {
		t.Fatal("session not shared")
	}
	nativeEcho(t, cl, l, []byte("after resets"))
}

func TestPhase31QUICSecurityPolicy(t *testing.T) {
	cl, _, _ := quicFixture(t)
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	impl := cl.impl.(*quicNativeClient)
	state := impl.conn.ConnectionState()
	if state.Version != quic.Version1 || state.TLS.NegotiatedProtocol != cfg.GenericQUICALPN || state.TLS.DidResume || state.Used0RTT || state.SupportsDatagrams.Remote {
		t.Fatalf("unexpected negotiation %+v", state)
	}
	for _, server := range []bool{false, true} {
		q := genericQUICConfig(server)
		if q.Allow0RTT || q.EnableDatagrams || q.KeepAlivePeriod != 0 || q.MaxIncomingUniStreams != -1 {
			t.Fatal("unsafe defaults")
		}
		tc, e := genericQUICTLS(&tls.Config{ServerName: "native.synthetic.test"}, cfg.Config{Kind: "quic-stream"}, server)
		if e != nil || !tc.SessionTicketsDisabled || tc.ClientSessionCache != nil {
			t.Fatal("resumption not disabled", e)
		}
	}
}

func TestPhase31QUICTLSFailuresAndSessionLoss(t *testing.T) {
	good, l, count := quicFixture(t)
	base := good.impl.(*quicNativeClient)
	for _, mode := range []string{"wrong-sni", "untrusted", "wrong-alpn", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			tc := base.tls.Clone()
			switch mode {
			case "wrong-sni":
				tc.ServerName = "wrong.synthetic.test"
			case "untrusted":
				tc.RootCAs = x509.NewCertPool()
			case "wrong-alpn":
				tc.NextProtos = []string{"h3"}
			}
			cl, e := NewPacketClient(base.socket, cfg.Config{Kind: "quic-stream"}, tc)
			if e != nil {
				if mode != "wrong-alpn" {
					t.Fatal(e)
				}
				return
			}
			defer cl.Close()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			a, e := cl.DialContext(ctx)
			if e == nil {
				a.Close()
				t.Fatal("invalid QUIC admitted")
			}
		})
	}
	before := count.Load()
	nativeEcho(t, good, l, []byte("valid"))
	base.mu.Lock()
	q := base.conn
	base.mu.Unlock()
	if e := q.CloseWithError(9, "test failure"); e != nil {
		t.Fatal(e)
	}
	nativeEcho(t, good, l, []byte("fresh session after loss"))
	if count.Load()-before != 2 {
		t.Fatal("failed session not evicted", count.Load())
	}
}

func TestPhase31QUICCloseInterrupts(t *testing.T) {
	cl, l, _ := quicFixture(t)
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	a.Write([]byte{1})
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	io.ReadFull(b, make([]byte, 1))
	done := make(chan error, 1)
	go func() { _, e := a.Read(make([]byte, 1)); done <- e }()
	cl.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read survived close")
		}
	case <-time.After(time.Second):
		t.Fatal("orphan read")
	}
	if _, e = cl.DialContext(t.Context()); e == nil {
		t.Fatal("closed client redialed")
	}
	l.Close()
	if _, e = l.Accept(); e == nil {
		t.Fatal("closed listener accepted")
	}
}

func TestPhase31QUICActiveResetIsolation(t *testing.T) {
	cl, l, _ := quicFixture(t)
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	a.Write([]byte{1})
	b, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	b.SetDeadline(time.Now().Add(time.Second))
	io.ReadFull(b, make([]byte, 1))
	a.(*quicStreamConn).CancelWrite(42)
	if _, e = b.Read(make([]byte, 1)); e == nil {
		t.Fatal("reset not observed")
	}
	nativeEcho(t, cl, l, []byte("active sibling after RESET_STREAM"))
}

func TestPhase31QUICSimultaneous(t *testing.T) {
	cl, l, _ := quicFixture(t)
	nativeSimultaneous(t, cl, l)
}
