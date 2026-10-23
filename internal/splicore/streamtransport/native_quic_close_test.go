//go:build with_quic

package streamtransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// Observe actual peer-received STREAM_DATA_BLOCKED frames, rather than guessing
// that a writer has exhausted credit after a sleep. The peer never reads data.
type blockedTrace struct{ events chan quic.StreamID }

func (b *blockedTrace) AddProducer() qlogwriter.Recorder { return b }
func (b *blockedTrace) SupportsSchemas(string) bool      { return true }
func (b *blockedTrace) Close() error                     { return nil }
func (b *blockedTrace) RecordEvent(e qlogwriter.Event) {
	if p, ok := e.(qlog.PacketReceived); ok {
		for _, f := range p.Frames {
			if v, ok := f.Frame.(*qlog.StreamDataBlockedFrame); ok {
				select {
				case b.events <- v.StreamID:
				default:
				}
			}
		}
	}
}

// One endpoint is the production client/listener; the other is an unread raw
// QUIC peer with a tracer. Both roles therefore exercise real native wrappers.
func blockedQUICFixture(t *testing.T, side string) (func() (*quicStreamConn, *quic.Stream), func(), *blockedTrace, *atomic.Int32) {
	t.Helper()
	server, client := nativeTLSFixture(t)
	c := cfg.Config{Kind: "quic-stream"}
	trace := &blockedTrace{events: make(chan quic.StreamID, 128)}
	config := genericQUICConfig(side == "client")
	config.Tracer = func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return trace }
	releases := &atomic.Int32{}
	if side == "client" {
		tc, e := genericQUICTLS(server, c, true)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := quic.ListenAddr("127.0.0.1:0", tc, config)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { raw.Close() })
		cl, e := NewPacketClient(func(context.Context) (net.PacketConn, net.Addr, error) {
			p, e := net.ListenPacket("udp4", "127.0.0.1:0")
			return p, raw.Addr(), e
		}, c, client)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { cl.Close() })
		var peer *quic.Conn
		open := func() (*quicStreamConn, *quic.Stream) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			a, e := cl.DialContext(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = a.Write([]byte{1}); e != nil {
				t.Fatal(e)
			}
			if peer == nil {
				peer, e = raw.Accept(ctx)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() { peer.CloseWithError(0, "test complete") })
			}
			b, e := peer.AcceptStream(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = io.ReadFull(b, make([]byte, 1)); e != nil {
				t.Fatal(e)
			}
			s := a.(*quicStreamConn)
			release := s.release
			s.release = func() { release(); releases.Add(1) }
			return s, b
		}
		return open, func() { cl.Close() }, trace, releases
	}
	base, e := ListenCarrier(t.Context(), "127.0.0.1:0", c)
	if e != nil {
		t.Fatal(e)
	}
	l, e := WrapListener(base, c, server)
	if e != nil {
		base.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	tc, e := genericQUICTLS(client, c, false)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	peer, e := quic.DialAddr(ctx, l.Addr().String(), tc, config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peer.CloseWithError(0, "test complete") })
	open := func() (*quicStreamConn, *quic.Stream) {
		b, e := peer.OpenStreamSync(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = b.Write([]byte{1}); e != nil {
			t.Fatal(e)
		}
		a, e := l.Accept()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(a, make([]byte, 1)); e != nil {
			t.Fatal(e)
		}
		s := a.(*quicStreamConn)
		s.release = func() { releases.Add(1) }
		return s, b
	}
	return open, func() { l.Close() }, trace, releases
}

func awaitQUICError(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case e := <-done:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("stream operation did not return")
		return nil
	}
}

func TestPhase31QUICBlockedWriteFullClose(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			open, _, trace, releases := blockedQUICFixture(t, side)
			for cycle := range 4 {
				s, peer := open()
				writeDone := make(chan error, 1)
				readDone := make(chan error, 1)
				go func() { _, e := s.Write(bytes.Repeat([]byte{7}, 8<<20)); writeDone <- e }()
				go func() { _, e := s.Read(make([]byte, 1)); readDone <- e }()
				deadline := time.NewTimer(3 * time.Second)
			blocked:
				for {
					select {
					case id := <-trace.events:
						if id == s.StreamID() {
							break blocked
						}
					case e := <-writeDone:
						t.Fatalf("write completed before flow-control exhaustion: %v", e)
					case <-deadline.C:
						t.Fatal("no STREAM_DATA_BLOCKED observed")
					}
				}
				deadline.Stop()
				select {
				case e := <-writeDone:
					t.Fatalf("flow-controlled write unexpectedly completed: %v", e)
				default:
				}
				t.Logf("cycle %d stream %d: peer observed real STREAM_DATA_BLOCKED", cycle, s.StreamID())
				closes := make(chan error, 9)
				// CloseWrite may queue behind Write; full Close must bypass that queue.
				go func() { closes <- s.CloseWrite() }()
				for range 8 {
					go func() { closes <- s.Close() }()
				}
				for range 9 {
					e := awaitQUICError(t, closes)
					if e != nil && !errors.Is(e, net.ErrClosed) {
						t.Fatal(e)
					}
				}
				var streamErr *quic.StreamError
				e := awaitQUICError(t, writeDone)
				if !errors.As(e, &streamErr) || streamErr.Remote || streamErr.ErrorCode != 1 {
					t.Fatalf("local stream cancellation required: %T %v", e, e)
				}
				if e = awaitQUICError(t, readDone); e == nil {
					t.Fatal("read survived full close")
				}
				if _, e = s.Write([]byte{1}); !errors.Is(e, net.ErrClosed) {
					t.Fatal("write after close", e)
				}
				peer.CancelRead(1)
				peer.CancelWrite(1)
				// A new stream on exactly the same connection must retain byte integrity.
				sibling, remote := open()
				if sibling.connection != s.connection {
					t.Fatal("connection replaced")
				}
				payload := []byte("healthy sibling")
				if _, e = sibling.Write(payload); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(payload))
				remote.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, e = io.ReadFull(remote, got); e != nil || !bytes.Equal(got, payload) {
					t.Fatal(got, e)
				}
				if _, e = remote.Write(payload); e != nil {
					t.Fatal(e)
				}
				sibling.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, e = io.ReadFull(sibling, got); e != nil || !bytes.Equal(got, payload) {
					t.Fatal(got, e)
				}
				sibling.Close()
				remote.CancelRead(1)
				remote.CancelWrite(1)
			}
			if releases.Load() != 8 {
				t.Fatal("release count", releases.Load())
			}
		})
	}
}

func TestPhase31QUICShutdownBlockedChildren(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			open, shutdown, trace, _ := blockedQUICFixture(t, side)
			var children []*quicStreamConn
			done := make(chan error, 2)
			for range 2 {
				s, _ := open()
				children = append(children, s)
				go func() { _, e := s.Write(bytes.Repeat([]byte{5}, 8<<20)); done <- e }()
				timer := time.NewTimer(3 * time.Second)
			blocked:
				for {
					select {
					case id := <-trace.events:
						if id == s.StreamID() {
							break blocked
						}
					case <-timer.C:
						t.Fatal("no flow-control block")
					}
				}
				timer.Stop()
			}
			closed := make(chan error, 1)
			go func() { shutdown(); closed <- nil }()
			awaitQUICError(t, closed)
			for range children {
				if e := awaitQUICError(t, done); e == nil {
					t.Fatal("child write survived shutdown")
				}
			}
		})
	}
}
