//go:build with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func nativeReadBlocked(t *testing.T, p *routedPacket) {
	t.Helper()
	limit := time.Now().Add(time.Second)
	for time.Now().Before(limit) {
		p.mu.Lock()
		registered := len(p.reads) != 0
		p.mu.Unlock()
		if registered {
			// The public adapter has no waiter introspection. Yield past its
			// registered entry into the real gVisor blocking read call.
			time.Sleep(time.Millisecond)
			return
		}
		time.Sleep(100 * time.Microsecond)
	}
	t.Fatal("native read did not register")
}

func nativeReadResult(t *testing.T, done <-chan packetReadResult, want error) []byte {
	t.Helper()
	select {
	case result := <-done:
		if !errors.Is(result.err, want) {
			t.Fatalf("native read err=%v want=%v", result.err, want)
		}
		var timeout net.Error
		isTimeout := errors.As(result.err, &timeout) && timeout.Timeout()
		if errors.Is(want, os.ErrDeadlineExceeded) && !isTimeout {
			t.Fatalf("read deadline lacks net.Error.Timeout: %v", result.err)
		}
		if errors.Is(want, net.ErrClosed) && isTimeout {
			t.Fatalf("read Close classified as timeout: %v", result.err)
		}
		return result.data
	case <-time.After(time.Second):
		t.Fatal("native read remained blocked")
		return nil
	}
}

func nativeReadPacket(t *testing.T, e *Endpoint) *routedPacket {
	t.Helper()
	c, err := e.ListenPacket(context.Background(), access.Endpoint{Host: "10.34.0.2", Port: 12346})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.(*routedPacket)
}

func TestWireGuardReadClose200(t *testing.T) {
	a, _, _, _ := pair(t, false)
	var last *routedPacket
	for range 200 {
		p := nativeReadPacket(t, a)
		done := packetStartRead(p)
		nativeReadBlocked(t, p)
		start := time.Now()
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		nativeReadResult(t, done, net.ErrClosed)
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Fatalf("Close/read wakeup took %s", elapsed)
		}
		packetIdle(t, p, &packetDNS{})
		last = p
	}
	for range 100 {
		_, _, err := last.ReadFrom(make([]byte, 128))
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal("native read after Close", err)
		}
	}
	t.Log("native blocked reads + Close: net.ErrClosed=200/200 timeout=0/200; reads after Close=100/100 net.ErrClosed")
}

func TestWireGuardReadDeadline(t *testing.T) {
	for _, mode := range []string{"preset", "after-start"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, _ := pair(t, false)
			p := nativeReadPacket(t, a)
			if mode == "preset" {
				_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			}
			done := packetStartRead(p)
			nativeReadBlocked(t, p)
			start := time.Now()
			if mode == "after-start" {
				if err := p.SetReadDeadline(start.Add(50 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			nativeReadResult(t, done, os.ErrDeadlineExceeded)
			if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
				t.Fatalf("native read deadline took %s", elapsed)
			} else {
				t.Logf("native %s read deadline=%s", mode, elapsed)
			}
			packetIdle(t, p, &packetDNS{})
		})
	}
}

func nativeSendToAssociation(t *testing.T, e *Endpoint, destination net.Addr, payload []byte) {
	t.Helper()
	host, port, err := net.SplitHostPort(destination.String())
	if err != nil {
		t.Fatal(err)
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.ListenPacket(context.Background(), access.Endpoint{Host: host, Port: uint16(number)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.WriteTo(payload, destination); err != nil {
		t.Fatal(err)
	}
}

func TestWireGuardReadDeadlineUpdate(t *testing.T) {
	for _, mode := range []string{"extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			a, b, _, _ := pair(t, false)
			transferUDP(t, a, "10.34.0.2", 32) // authenticate peer/learn its endpoint
			p := nativeReadPacket(t, a)
			done := packetStartRead(p)
			nativeReadBlocked(t, p)
			_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			time.Sleep(10 * time.Millisecond)
			deadline := time.Time{}
			if mode == "extend" {
				deadline = time.Now().Add(500 * time.Millisecond)
			}
			if err := p.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			time.Sleep(70 * time.Millisecond)
			packetReadPending(t, done)
			payload := []byte("native read " + mode)
			nativeSendToAssociation(t, b, p.LocalAddr(), payload)
			if got := nativeReadResult(t, done, nil); !bytes.Equal(got, payload) {
				t.Fatalf("packet=%q want=%q", got, payload)
			}
			packetIdle(t, p, &packetDNS{})
		})
	}
}

func TestWireGuardReadAssociationIsolation(t *testing.T) {
	a, b, _, _ := pair(t, false)
	transferUDP(t, a, "10.34.0.2", 32)
	first, second := nativeReadPacket(t, a), nativeReadPacket(t, a)
	readingFirst, readingSecond := packetStartRead(first), packetStartRead(second)
	nativeReadBlocked(t, first)
	nativeReadBlocked(t, second)
	_ = first.Close()
	nativeReadResult(t, readingFirst, net.ErrClosed)
	packetReadPending(t, readingSecond)
	payload := []byte("another association remains alive")
	nativeSendToAssociation(t, b, second.LocalAddr(), payload)
	if got := nativeReadResult(t, readingSecond, nil); !bytes.Equal(got, payload) {
		t.Fatalf("isolated read=%q", got)
	}
	if a.Status().State != Active {
		t.Fatal("association Close shut down the endpoint")
	}
	transferTCP(t, a, "10.34.0.2")
	transferUDP(t, a, "fd34::2", 64)
	packetIdle(t, first, &packetDNS{})
	packetIdle(t, second, &packetDNS{})
}

func TestWireGuardReadWriteEndpointClose(t *testing.T) {
	a, _, _, _ := pair(t, false)
	d := &packetDNS{release: make(chan struct{})}
	a.options.LookupHost = d.lookup
	p := nativeReadPacket(t, a)
	audit := &packetDeadlineAudit{PacketConn: p.PacketConn}
	p.PacketConn = audit
	if err := p.SetDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	reading, writing := packetStartRead(p), packetStart(p)
	nativeReadBlocked(t, p)
	limit := time.Now().Add(time.Second)
	for d.active.Load() == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if d.active.Load() != 1 {
		t.Fatal("Core DNS not entered")
	}
	closedStatus(t, a)
	nativeReadResult(t, reading, net.ErrClosed)
	select {
	case err := <-writing:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("endpoint Close did not join write")
	}
	packetIdle(t, p, d)
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if !audit.read.IsZero() || !audit.write.IsZero() || audit.closeCalls != 1 {
		t.Fatalf("transport timers not disarmed by completion: read=%v write=%v closeCalls=%d", audit.read, audit.write, audit.closeCalls)
	}
}
