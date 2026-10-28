//go:build with_quic

package xhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h3ReleasedPacket struct {
	net.PacketConn
	closed, resume chan struct{}
}

func (p *h3ReleasedPacket) Close() error {
	err := p.PacketConn.Close()
	close(p.closed)
	<-p.resume
	return err
}

// B must retain its own terminal authority while retired A's socket Close is
// still returning. Physical ownership, rather than either local port, identifies
// the connection throughout that overlap.
func TestXHTTPH3ReclamationReleasedEndpointReuse(t *testing.T) {
	cl, front := h3RetryFixture(t, "packet-up", nil)
	front.reject.Store(false)
	original := cl.security.PacketSocket
	gates := make(chan *h3ReleasedPacket, 1)
	var dials atomic.Int32
	cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
		p, a, err := original(ctx)
		if err == nil && dials.Add(1) == 1 {
			gate := &h3ReleasedPacket{p, make(chan struct{}), make(chan struct{})}
			gates <- gate
			return gate, a, nil
		}
		return p, a, err
	}
	probe := h3ReclaimTrackClient(t, cl)
	e := h3RetryPrime(t, cl)
	a := front.connection(t)
	old := probe.snapshot()[0]
	gate := carrierReceive(t, gates)
	var once sync.Once
	unblock := func() { once.Do(func() { close(gate.resume) }) }
	defer unblock()
	h := e.transport.(*h3Transport)
	front.reject.Store(true)
	retried := make(chan h3CarrierResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := cl.DialContext(ctx)
		retried <- h3CarrierResult{c, err}
	}()
	carrierReceive(t, gate.closed)
	h.mu.Lock()
	retiring := old.socket.owner.retiring && old.socket.owner.refs == 0 && h.cached != old.socket.owner
	h.mu.Unlock()
	if !retiring || old.socket.conn.Context().Err() == nil {
		t.Fatal("old connection did not retire before replacement")
	}
	if err := probe.retired(old); err == nil {
		t.Fatal("retirement oracle accepted incomplete old socket Close")
	}

	// OPTIONS proves that B is healthy before exercising session watches.
	r, _ := http.NewRequest(http.MethodOptions, cl.URL().String(), nil)
	resp, err := e.request(r)
	if err != nil {
		t.Fatal("replacement OPTIONS", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal("replacement OPTIONS body", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("replacement OPTIONS status", resp.StatusCode)
	}
	b := front.connection(t)
	current := probe.snapshot()[1]
	if a.Conn == b.Conn || old == current || old.socket == current.socket || old.socket.owner == current.socket.owner || old.socket.conn == current.socket.conn {
		t.Fatal("replacement reused the old physical connection or owner")
	}
	h.mu.Lock()
	healthy := h.cached == current.socket.owner && h.sockets[current.socket] && h.carriers[current.socket.owner]
	h.mu.Unlock()
	if !healthy || current.socket.conn.Context().Err() != nil {
		t.Fatal("replacement is not the healthy cached connection")
	}
	var failed int
	for range 16 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := cl.DialContext(ctx)
		cancel()
		if err != nil {
			failed++
			t.Log("healthy replacement session failed", err)
			continue
		}
		s := h3CarrierSession(t, cl, c)
		exchange(t, c, []byte("different physical connection during old cleanup"))
		c.Close()
		h3AwaitTerminal(t, s)
	}
	if failed != 0 {
		t.Fatalf("retired A affected %d/16 healthy B sessions", failed)
	}
	if dials.Load() != 2 {
		t.Fatal("healthy replacement was not reused during old cleanup", dials.Load())
	}
	c, s := h3DialSession(t, cl)
	unblock()
	result := carrierReceive(t, retried)
	if result.err != nil {
		t.Fatal("original retry after A cleanup", result.err)
	}
	retriedSession := h3CarrierSession(t, cl, result.conn)
	result.conn.Close()
	h3AwaitTerminal(t, retriedSession)
	exchange(t, c, []byte("B survives completion of A cleanup"))
	c.Close()
	h3AwaitTerminal(t, s)
	h3ReclaimAwait(t, func() bool { return probe.retired(old) == nil })
	h3ReclaimBound(t, h, 1, 1, 0)
	// The original rejected request may install its own replacement when it
	// resumes. That cache transition must leave B's active session intact above,
	// and subsequent sessions must reuse the single healthy idle carrier.
	before := dials.Load()
	idle, idleSession := h3DialSession(t, cl)
	exchange(t, idle, []byte("idle carrier reused after old cleanup"))
	idle.Close()
	h3AwaitTerminal(t, idleSession)
	h3ReclaimBound(t, h, 1, 1, 0)
	if dials.Load() != before {
		t.Fatal("healthy idle carrier was not reused", before, dials.Load())
	}
	cl.Close()
	h3ReclaimBound(t, h, 0, 0, 0)
	for _, p := range probe.snapshot() {
		h3ReclaimAwait(t, func() bool { return probe.retired(p) == nil })
	}
	t.Log("old owner retired; 16/16 healthy sessions; old cleanup preserved active B; idle carrier reused; owner Close released all resources")
}
