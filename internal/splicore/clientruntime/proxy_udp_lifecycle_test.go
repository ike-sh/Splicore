package clientruntime

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dyingProxyPackets struct {
	net.PacketConn
	replies                        chan []byte
	kill, closed, closing, release chan struct{}
	once                           sync.Once
	address                        net.Addr
}

func (p *dyingProxyPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-p.kill:
		return 0, nil, io.EOF
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case v := <-p.replies:
		return copy(b, v), p.address, nil
	}
}
func (p *dyingProxyPackets) WriteTo(b []byte, a net.Addr) (int, error) {
	p.replies <- append([]byte(nil), b...)
	return len(b), nil
}
func (p *dyingProxyPackets) Close() error {
	p.once.Do(func() {
		close(p.closing)
		if p.release != nil {
			<-p.release
		}
		close(p.closed)
	})
	return nil
}
func (p *dyingProxyPackets) SetReadDeadline(time.Time) error  { return nil }
func (p *dyingProxyPackets) SetWriteDeadline(time.Time) error { return nil }

type replacementProxyDialer struct {
	created chan *dyingProxyPackets
	count   atomic.Int64
}

func (*replacementProxyDialer) DialContext(context.Context, access.Endpoint) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (*replacementProxyDialer) Close() error { return nil }
func (d *replacementProxyDialer) ListenPacket(_ context.Context, e access.Endpoint) (net.PacketConn, error) {
	p := &dyingProxyPackets{replies: make(chan []byte, 8), kill: make(chan struct{}), closed: make(chan struct{}), closing: make(chan struct{}), address: &net.UDPAddr{IP: net.ParseIP(e.Host), Port: int(e.Port)}}
	if d.count.Add(1) == 1 {
		p.release = make(chan struct{})
	}
	d.created <- p
	return p, nil
}
func TestPhase20UDPReaderDeathSameKeyReplacement(t *testing.T) {
	m, state, _, echo := udpFixture(t)
	d := &replacementProxyDialer{created: make(chan *dyingProxyPackets, 8)}
	m.current.Load().outbounds[client.Direct].(*dialerLease).dialer = d
	control, relay, e := udpControl(state, testfixture.Endpoint("0.0.0.0:0"))
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	pc, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	if e = udpRoundtrip(pc, relay, echo.LocalAddr(), []byte("first")); e != nil {
		t.Fatal(e)
	}
	old := <-d.created
	close(old.kill)
	select {
	case <-old.closing:
	case <-time.After(time.Second):
		t.Fatal("reader death did not mark owner dead")
	}
	// The old owner is dead but cannot yet deliver its retirement notification.
	if e = udpRoundtrip(pc, relay, echo.LocalAddr(), []byte("replacement")); e != nil {
		close(old.release)
		t.Fatal(e)
	}
	replacement := <-d.created
	close(old.release)
	select {
	case <-old.closed:
	case <-time.After(time.Second):
		t.Fatal("old owner did not close")
	}
	// Synchronize notification publication before draining it with another packet.
	for range 16 {
		// A response itself proves the replacement survived any queued retirement;
		// repeat across scheduling turns without imposing a production timing fix.
		if e = udpRoundtrip(pc, relay, echo.LocalAddr(), []byte("same-key-live")); e != nil {
			t.Fatal(e)
		}
		if d.count.Load() != 2 {
			break
		}
	}
	if d.count.Load() != 2 {
		t.Fatal("old owner deleted live replacement", d.count.Load())
	}
	_ = control.Close()
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = m.WaitIdle(wait); e != nil {
		t.Fatal(e)
	}
	select {
	case <-replacement.closed:
	default:
		t.Fatal("replacement retained after control Close")
	}
	t.Log("reader death, delayed old retirement, same-key replacement, payload and parent cleanup PASS")
}

func TestPhase20UDPAssociationChurn(t *testing.T) {
	m, state, _, echo := udpFixture(t)
	pc, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	for range 256 {
		control, relay, e := udpControl(state, testfixture.Endpoint("0.0.0.0:0"))
		if e != nil {
			t.Fatal(e)
		}
		if e = udpRoundtrip(pc, relay, echo.LocalAddr(), []byte("churn")); e != nil {
			control.Close()
			t.Fatal(e)
		}
		control.Close()
	}
	wait, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e = m.WaitIdle(wait); e != nil {
		t.Fatal(e)
	}
	v := m.Status(state, nil).Outbounds[0].Stats
	if v.UDPAssociations != 256 || v.UDPActive != 0 || v.PacketsDownload != 256 {
		t.Fatalf("UDP churn residue %+v", v)
	}
	t.Logf("256 UDP associations payload PASS; end=%+v", v)
}
