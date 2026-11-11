package clientruntime

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

type phase15UDPControlConn struct {
	net.Conn
	readyOnce, closeOnce sync.Once
	ready, closed        chan struct{}
}

func (c *phase15UDPControlConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *phase15UDPControlConn) Write(b []byte) (int, error) {
	c.readyOnce.Do(func() { close(c.ready) })
	return len(b), nil
}
func (c *phase15UDPControlConn) Close() error { c.closeOnce.Do(func() { close(c.closed) }); return nil }
func (*phase15UDPControlConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}
func (*phase15UDPControlConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346}
}
func (*phase15UDPControlConn) SetDeadline(time.Time) error { return nil }

// Hold the real UDP OS handle through RawConn.Control while cancellation closes
// it. A second Close can return early; the actual handler must await the first
// owner's completion before retirement. This exercises serveUDP directly.
func TestPhase15UDPCancellationCloseJoin(t *testing.T) {
	m := &Manager{udpIdle: time.Minute}
	control := &phase15UDPControlConn{ready: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{cancel: cancel, local: control}
	retired := make(chan struct{})
	go func() { m.serveUDP(ctx, s, control, access.Endpoint{Host: "0.0.0.0"}, &snapshot{}); close(retired) }()
	select {
	case <-control.ready:
	case <-time.After(time.Second):
		t.Fatal("UDP relay was not advertised")
	}
	m.mu.Lock()
	relay, ok := s.packet.(*net.UDPConn)
	m.mu.Unlock()
	if !ok {
		t.Fatal("actual UDP relay not owned")
	}
	raw, err := relay.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	held, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unhold := func() { once.Do(func() { close(release) }) }
	defer unhold()
	handleDone := make(chan error, 1)
	go func() { handleDone <- raw.Control(func(uintptr) { close(held); <-release }) }()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("OS handle was not held")
	}
	cancel()
	// Both old and fixed paths must reach local-control cleanup. The old callback
	// is then blocked owning the relay close; the duplicate handler Close returns.
	select {
	case <-control.closed:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not close control")
	}
	timer := time.NewTimer(50 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-retired:
		t.Fatal("session retired before the cancellation close completed")
	case <-timer.C:
	}
	unhold()
	if err = <-handleDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-retired:
	case <-time.After(time.Second):
		t.Fatal("UDP handler did not join after OS handle release")
	}
}
