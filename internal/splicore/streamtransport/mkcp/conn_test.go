package mkcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func tuning() cfg.MKCP { m := cfg.DefaultMKCP(); m.TTI = 10; return m }

// These synthetic wire tests explicitly model a successful UDP handoff. tick
// itself only plans pending output; blocked/full-queue tests exercise that state.
func handedPackets(c *Conn, now time.Time) [][]byte {
	var packets [][]byte
	for _, p := range c.tick(now) {
		b, ok := p.prepare(now)
		if ok {
			packets = append(packets, b)
		}
		p.finish(ok, now)
	}
	return packets
}
func waitDone(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(4 * time.Second):
		t.Fatal("owner did not join")
	}
}

// Each direction owns its deterministic packet schedule. Holds are flushed by
// the next matching packet, including retries; no sleeps or random loss exist.
type impairment struct {
	mu       sync.Mutex
	profile  string
	counts   map[byte]int
	held     map[byte][]byte
	affected int
	maximum  int
}

func (f *impairment) deliver(peer *Conn, b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(b) > f.maximum {
		f.maximum = len(b)
	}
	rows, e := decode(b, 1460)
	if e != nil {
		return e
	}
	code := rows[0].code
	f.counts[code]++
	n := f.counts[code]
	drop := f.profile == "data-loss" && code == dataCode && n == 1 || f.profile == "ack-loss" && code == ackCode && n <= 3 || f.profile == "periodic" && code == dataCode && n%7 == 0 || f.profile == "burst" && code == dataCode && n >= 4 && n <= 6 || f.profile == "control-loss" && (code == helloCode || code == endCode) && n == 1
	if drop {
		f.affected++
		return nil
	}
	reorder := (f.profile == "reorder" || f.profile == "delay") && code == dataCode || f.profile == "ack-reorder" && code == ackCode
	if reorder && n%5 == 1 {
		f.held[code] = append([]byte(nil), b...)
		f.affected++
		return nil
	}
	peer.input(rows)
	if held := f.held[code]; held != nil {
		r, _ := decode(held, 1460)
		peer.input(r)
		delete(f.held, code)
	}
	if f.profile == "duplicate" {
		peer.input(rows)
		f.affected++
	}
	return nil
}
func pair(t *testing.T, profile string, m cfg.MKCP) (*Conn, *Conn, *impairment, *impairment) {
	t.Helper()
	aAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	bAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	a := newConn(m, 13, aAddr, bAddr, nil, nil)
	b := newConn(m, 13, bAddr, aAddr, nil, nil)
	first := &impairment{profile: profile, counts: map[byte]int{}, held: map[byte][]byte{}}
	second := &impairment{profile: profile, counts: map[byte]int{}, held: map[byte][]byte{}}
	a.send = func(p []byte) error { return first.deliver(b, p) }
	b.send = func(p []byte) error { return second.deliver(a, p) }
	a.clock.end = 300 * time.Millisecond
	b.clock.end = 300 * time.Millisecond
	go a.run()
	go b.run()
	t.Cleanup(func() { a.abort(net.ErrClosed); b.abort(net.ErrClosed); waitDone(t, a.Done()); waitDone(t, b.Done()) })
	return a, b, first, second
}
func payload(n int, offset int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*31 + offset)
	}
	return p
}
func exchange(t *testing.T, a, b *Conn, n int, small bool) {
	t.Helper()
	a.SetDeadline(time.Now().Add(15 * time.Second))
	b.SetDeadline(time.Now().Add(15 * time.Second))
	var wg sync.WaitGroup
	fail := make(chan error, 4)
	for direction, ends := range [][2]*Conn{{a, b}, {b, a}} {
		want := payload(n, direction+7)
		sender, reader := ends[0], ends[1]
		wg.Add(2)
		go func() {
			defer wg.Done()
			if small {
				for _, v := range want {
					if _, e := sender.Write([]byte{v}); e != nil {
						fail <- e
						return
					}
				}
			} else {
				if _, e := sender.Write(want); e != nil {
					fail <- e
				}
			}
		}()
		go func() {
			defer wg.Done()
			got := make([]byte, n)
			_, e := io.ReadFull(reader, got)
			if e != nil {
				fail <- e
			} else if !bytes.Equal(got, want) {
				fail <- errors.New("payload corruption, duplicate or ordering error")
			}
		}()
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		t.Error(err)
	}
}
func TestReliableFullDuplexImpairment(t *testing.T) {
	for _, profile := range []string{"normal", "data-loss", "ack-loss", "periodic", "burst", "reorder", "delay", "ack-reorder", "duplicate", "control-loss"} {
		t.Run(profile, func(t *testing.T) {
			m := tuning()
			a, b, f, g := pair(t, profile, m)
			exchange(t, a, b, 128<<10, false)
			a.Close()
			b.Close()
			waitDone(t, a.Done())
			waitDone(t, b.Done())
			f.mu.Lock()
			defer f.mu.Unlock()
			g.mu.Lock()
			defer g.mu.Unlock()
			if f.maximum > int(m.MTU) || g.maximum > int(m.MTU) {
				t.Fatal("oversized datagram")
			}
			if profile != "normal" && f.affected+g.affected == 0 {
				t.Fatal("impairment was not exercised")
			}
			t.Logf("profile=%s injected=%d datagram_max=%d", profile, f.affected+g.affected, f.maximum)
		})
	}
}

// Consuming a complete window removes its selective receipts. If the last
// cumulative/window ACK is lost, an otherwise idle sender still needs a repeat.
// A synthetic clock verifies recovery without relying on a fortunate schedule.
func TestConsumedWindowACKRepeatsWithoutOutstandingReceipts(t *testing.T) {
	m := tuning()
	m.DownlinkCapacity = 0
	c := newConn(m, 13, nil, nil, nil, nil)
	for n := uint32(0); n < m.ReceiveSlots(); n++ {
		c.input([]record{{token: 13, code: dataCode, sequence: n, data: []byte{byte(n)}}})
		if _, e := c.Read(make([]byte, 1)); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now()
	check := func(packets [][]byte) {
		t.Helper()
		for _, p := range packets {
			rows, e := decode(p, 1460)
			if e != nil {
				t.Fatal(e)
			}
			for _, r := range rows {
				if r.code == ackCode && r.next == m.ReceiveSlots() && r.edge == 2*m.ReceiveSlots() && len(r.numbers) == 0 {
					return
				}
			}
		}
		t.Fatal("consumed window has no cumulative/window ACK")
	}
	check(handedPackets(c, now)) // Deliberately discard the only fresh ACK on the wire.
	if len(c.ack) != 0 {
		t.Fatal("consumed selective receipts retained")
	}
	check(handedPackets(c, now.Add(100*time.Millisecond)))
}
func TestPayloadMTUAndWriteBoundaries(t *testing.T) {
	for _, mtu := range []uint32{576, 1000, 1350, 1460} {
		t.Run(fmt.Sprint(mtu), func(t *testing.T) {
			m := tuning()
			m.MTU = mtu
			a, b, _, _ := pair(t, "normal", m)
			for _, n := range []int{1, 13, int(mtu) - 1, int(mtu), int(mtu) + 1, 65537, 1048577, 3 << 20} {
				exchange(t, a, b, n, false)
			}
			exchange(t, a, b, 2048, true)
		})
	}
}
func TestLiveDeadlinesAndCloseDuringIO(t *testing.T) {
	m := tuning()
	m.MaxSendingWindow = m.MTU
	c := newConn(m, 1, nil, nil, func([]byte) error { return nil }, nil)
	go c.run()
	t.Cleanup(func() { c.abort(net.ErrClosed); waitDone(t, c.Done()) })
	read := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); read <- e }()
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if e := <-read; !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("live read deadline", e)
	}
	c.SetReadDeadline(time.Time{})
	go func() { _, e := c.Read(make([]byte, 1)); read <- e }()
	write := make(chan error, 1)
	go func() { _, e := c.Write(make([]byte, 5000)); write <- e }()
	c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	if e := <-write; !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("live write deadline", e)
	}
	c.SetWriteDeadline(time.Time{})
	go func() { _, e := c.Write(make([]byte, 1)); write <- e }()
	c.Close()
	if e := <-read; !errors.Is(e, net.ErrClosed) {
		t.Fatal("close read", e)
	}
	if e := <-write; !errors.Is(e, net.ErrClosed) {
		t.Fatal("close write", e)
	}
	c.mu.Lock()
	if len(c.out) > int(m.QueueSlots()) {
		t.Fatal("unbounded send queue")
	}
	c.mu.Unlock()
}
func TestDeadPeerAndGracefulReadDrain(t *testing.T) {
	m := tuning()
	var releases atomic.Int32
	c := newConn(m, 1, nil, nil, func([]byte) error { return nil }, func() { releases.Add(1) })
	c.clock.idle = 50 * time.Millisecond
	go c.run()
	waitDone(t, c.Done())
	if releases.Load() != 1 {
		t.Fatal("dead peer admission release")
	}
	if _, e := c.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal(e)
	}
	a, b, _, _ := pair(t, "normal", m)
	p := payload(65537, 3)
	if _, e := a.Write(p); e != nil {
		t.Fatal(e)
	}
	a.Close()
	b.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, e := io.ReadAll(b)
	if e != nil || !bytes.Equal(got, p) {
		t.Fatal("remote close lost pending bytes", len(got), e)
	}
	waitDone(t, a.Done())
	waitDone(t, b.Done())
}
func TestReceiveACKBoundsAndWrongToken(t *testing.T) {
	m := tuning()
	m.DownlinkCapacity = 0
	c := newConn(m, 7, nil, nil, nil, nil)
	for n := uint32(0); n < 1000; n++ {
		c.input([]record{{token: 7, code: dataCode, sequence: n, data: []byte{byte(n)}}})
	}
	if len(c.in) != 8 || len(c.ack) != 8 {
		t.Fatal("receive bounds")
	}
	c.input([]record{{token: 8, code: endCode}})
	if c.remoteEOF {
		t.Fatal("wrong token mutated state")
	}
	for n := uint32(0); n < 500; n++ {
		b := make([]byte, 1)
		if _, e := c.Read(b); e != nil {
			t.Fatal(e)
		}
		c.input([]record{{token: 7, code: dataCode, sequence: n + 8, data: []byte{byte(n)}, floor: 0}})
		if len(c.in) > 8 || len(c.ack) > 8 {
			t.Fatal("ACK/reorder grew with stale floor")
		}
	}
	c.abort(net.ErrClosed)
}
func TestWindowMultiplierAndWrapRecovery(t *testing.T) {
	count := func(mult uint32) int {
		m := tuning()
		m.UplinkCapacity = 0
		m.CWNDMultiplier = mult
		c := newConn(m, 1, nil, nil, nil, nil)
		c.remoteEdge = 100
		c.Write(make([]byte, 20*(int(m.MTU)-dataHeader)))
		rows := handedPackets(c, c.birth.Add(10*time.Millisecond))
		n := 0
		for _, b := range rows {
			if b[2] == dataCode {
				n++
			}
		}
		return n
	}
	if count(1) != 8 || count(2) != 16 {
		t.Fatal("ignored multiplier")
	}
	m := tuning()
	c := newConn(m, 1, nil, nil, nil, nil)
	c.sendNext = 0xfffffffe
	c.remoteEdge = 5
	c.Write(make([]byte, 3*(int(m.MTU)-dataHeader)))
	c.input([]record{{token: 1, code: ackCode, edge: 5, next: 0, numbers: []uint32{0}}})
	if len(c.out) != 0 {
		t.Fatal("wrapped cumulative/selective ACK")
	}
}

func udpListener(t *testing.T, network, address string, m cfg.MKCP) *Listener {
	t.Helper()
	p, e := net.ListenPacket(network, address)
	if e != nil {
		if network == "udp6" && (errors.Is(e, syscall.EAFNOSUPPORT) || errors.Is(e, syscall.EADDRNOTAVAIL) || errors.Is(e, syscall.EPROTONOSUPPORT)) {
			t.Skip("IPv6 unavailable:", e)
		}
		t.Fatal(e)
	}
	l, e := NewListener(p, m)
	if e != nil {
		p.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	return l
}
func TestUDPMultipleSessionsFamiliesAndChurn(t *testing.T) {
	for _, family := range []struct{ network, address string }{{"udp4", "127.0.0.1:0"}, {"udp6", "[::1]:0"}} {
		t.Run(family.network, func(t *testing.T) {
			m := tuning()
			m.UplinkCapacity = 0
			m.DownlinkCapacity = 0
			m.MaxSendingWindow = 8 * m.MTU
			l := udpListener(t, family.network, family.address, m)
			if _, e := net.ListenPacket(family.network, l.Addr().String()); e == nil {
				t.Fatal("port conflict not rejected")
			}
			var wg sync.WaitGroup
			fail := make(chan error, 256)
			accepted := make(chan struct{})
			go func() {
				defer close(accepted)
				for i := 0; i < 256; i++ {
					raw, e := l.Accept()
					if e != nil {
						fail <- e
						return
					}
					c := raw.(*Conn)
					wg.Add(1)
					go func() {
						defer wg.Done()
						c.SetDeadline(time.Now().Add(3 * time.Second))
						got := make([]byte, 64)
						if _, e := io.ReadFull(c, got); e != nil {
							fail <- e
						} else if _, e = c.Write(got); e != nil {
							fail <- e
						}
						c.Close()
						<-c.Done()
					}()
				}
			}()
			for batch := 0; batch < 32; batch++ {
				var clients sync.WaitGroup
				for j := 0; j < 8; j++ {
					id := batch*8 + j
					clients.Add(1)
					go func() {
						defer clients.Done()
						d := net.Dialer{}
						c, e := Dial(context.Background(), d.DialContext, l.Addr().String(), m)
						if e != nil {
							fail <- e
							return
						}
						defer c.Close()
						c.SetDeadline(time.Now().Add(3 * time.Second))
						want := payload(64, id)
						c.Write(want)
						got := make([]byte, 64)
						_, e = io.ReadFull(c, got)
						if e != nil || !bytes.Equal(got, want) {
							fail <- fmt.Errorf("session %d integrity: %v", id, e)
						}
						c.Close()
						<-c.Done()
					}()
				}
				clients.Wait()
			}
			waitDone(t, accepted)
			wg.Wait()
			if l.ActiveSessions() != 0 {
				t.Fatal("churn sessions retained", l.ActiveSessions())
			}
			l.Close()
			close(fail)
			for e := range fail {
				t.Error(e)
			}
			t.Log("sessions=256 concurrent=8 active_end=0 owner_barriers=joined")
		})
	}
}
func TestListenerMalformedStaleIsolationAndAdmission(t *testing.T) {
	m := tuning()
	m.DownlinkCapacity = 0
	m.UplinkCapacity = 0
	m.MaxSendingWindow = m.MTU
	l := udpListener(t, "udp4", "127.0.0.1:0", m)
	a, e := net.Dial("udp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := net.Dial("udp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	for _, c := range []net.Conn{a, b} {
		c.Write(encode(record{token: 2, code: dataCode, data: []byte(c.LocalAddr().String())}))
	}
	first, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	second, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []net.Conn{first, second} {
		buf := make([]byte, 100)
		n, e := c.Read(buf)
		if e != nil || string(buf[:n]) != c.RemoteAddr().String() {
			t.Fatal("same token peers crossed", e)
		}
	}
	first.Close()
	first.(*Conn).abort(net.ErrClosed)
	waitDone(t, first.(*Conn).Done())
	a.Write(encode(record{token: 2, code: helloCode}))
	// A valid final packet acts as a receive-loop barrier for earlier malformed
	// and retired-token datagrams on the same UDP socket.
	for _, packet := range [][]byte{{1, 2, 3}, encode(record{token: 99, code: ackCode}), encode(record{token: 99, code: endCode})} {
		a.Write(packet)
	}
	a.Write(encode(record{token: 3, code: dataCode, data: []byte("barrier")}))
	third, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	if third.(*Conn).token != 3 || l.ActiveSessions() != 2 {
		t.Fatal("phantom/stale sessions", l.ActiveSessions())
	}
	second.Close()
	third.Close()
	l.Close()
	if l.ActiveSessions() != 0 || l.reserved != 0 {
		t.Fatal("listener did not release reservations")
	}
	// Resource admission uses actual packet ownership and worst-case payload,
	// not the number of bytes received at admission time.
	l2 := udpListener(t, "udp4", "127.0.0.1:0", cfg.DefaultMKCP())
	probe, e := net.Dial("udp4", l2.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer probe.Close()
	probe.Write(encode(record{token: 0, code: helloCode}))
	admitted, e := l2.Accept()
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i < 80; i++ {
		probe.Write(encode(record{token: uint16(i), code: helloCode}))
	}
	probe.Write(encode(record{token: 0, code: dataCode, data: []byte("dispatch-barrier")}))
	admitted.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, e := admitted.Read(make([]byte, 100)); e != nil {
		t.Fatal(e)
	}
	l2.mu.Lock()
	maximum := int(uint64(listenerPayloadLimit) / l2.config.PayloadBound())
	if maximum > sessionLimit {
		maximum = sessionLimit
	}
	if len(l2.sessions) != maximum || l2.reserved > listenerPayloadLimit {
		t.Error("listener admission bound", len(l2.sessions), maximum, l2.reserved)
	}
	l2.mu.Unlock()
	l2.Close()
	if l2.reserved != 0 || l2.ActiveSessions() != 0 {
		t.Fatal("admission accounting leak")
	}
}
func TestDialCancellationFailureAndListenerShutdownIO(t *testing.T) {
	m := tuning()
	l := udpListener(t, "udp4", "127.0.0.1:0", m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if _, e := Dial(ctx, func(context.Context, string, string) (net.Conn, error) {
		called = true
		return nil, errors.New("unexpected")
	}, l.Addr().String(), m); !errors.Is(e, context.Canceled) || called {
		t.Fatal("canceled dial allocated socket", e)
	}
	ctx, cancel = context.WithCancel(context.Background())
	var owned net.Conn
	if _, e := Dial(ctx, func(ctx context.Context, n, a string) (net.Conn, error) {
		d := net.Dialer{}
		c, e := d.DialContext(ctx, n, a)
		owned = c
		cancel()
		return c, e
	}, l.Addr().String(), m); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := owned.Write([]byte{1}); e == nil {
		t.Fatal("canceled dial socket survived")
	}
	d := net.Dialer{}
	c, e := Dial(context.Background(), d.DialContext, l.Addr().String(), m)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Abort(net.ErrClosed)
	c.Write([]byte{1})
	server, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	read := make(chan error, 1)
	server.Read(make([]byte, 1))
	go func() { _, e := server.Read(make([]byte, 1)); read <- e }()
	l.Close()
	if e := <-read; !errors.Is(e, net.ErrClosed) {
		t.Fatal("listener shutdown did not wake read", e)
	}
	waitDone(t, server.(*Conn).Done())
}

func TestTerminalSessionDetachesWithBoundedReadableEOF(t *testing.T) {
	m := tuning()
	l := udpListener(t, "udp4", "127.0.0.1:0", m)
	peer, e := net.Dial("udp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	peer.Write(encode(record{token: 51, code: dataCode, data: []byte("retained")}))
	raw, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	c := raw.(*Conn)
	peer.Write(encode(record{token: 51, code: endCode}))
	waitDone(t, c.Done())
	l.mu.Lock()
	active, reserved, retained := len(l.sessions), l.reserved, len(l.held)
	l.mu.Unlock()
	if active != 0 || reserved != m.PayloadBound() || retained != 1 {
		t.Fatal("terminal session/reservation ownership", active, reserved, retained)
	}
	got, e := io.ReadAll(c)
	if e != nil || string(got) != "retained" {
		t.Fatal("buffered EOF", e, string(got))
	}
	l.mu.Lock()
	reserved, retained = l.reserved, len(l.held)
	l.mu.Unlock()
	if reserved != 0 || retained != 0 {
		t.Fatal("consumed reservation not released")
	}
	c.Close()
	l.Close()
	if l.reserved != 0 {
		t.Fatal("release ran twice")
	}
}

func TestMixedOutcomeChurn256(t *testing.T) {
	m := tuning()
	completed, canceled, failed, recovered, remote := 0, 0, 0, 0, 0
	for i := 0; i < 256; i++ {
		switch i % 4 {
		case 0:
			a, b, _, _ := pair(t, "data-loss", m)
			exchange(t, a, b, 4096, false)
			a.Close()
			b.Close()
			waitDone(t, a.Done())
			waitDone(t, b.Done())
			recovered++
		case 1:
			a, b, _, _ := pair(t, "normal", m)
			b.Close()
			waitDone(t, a.Done())
			waitDone(t, b.Done())
			remote++
		case 2:
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, e := Dial(ctx, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("canceled dial allocated")
				return nil, nil
			}, "unused", m); !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			canceled++
		case 3:
			want := errors.New("controlled dial failure")
			if _, e := Dial(context.Background(), func(context.Context, string, string) (net.Conn, error) { return nil, want }, "unused", m); !errors.Is(e, want) {
				t.Fatal(e)
			}
			failed++
		}
		completed++
	}
	if completed != 256 || canceled != 64 || failed != 64 || recovered != 64 || remote != 64 {
		t.Fatal("churn outcome count")
	}
	t.Logf("completed=%d canceled=%d dial_failure=%d loss_recovery=%d remote_close=%d transport_owners_remaining=0", completed, canceled, failed, recovered, remote)
}

func TestTimestampWrapRTTAndACKCompression(t *testing.T) {
	m := tuning()
	m.MTU = 576
	c := newConn(m, 4, nil, nil, nil, nil)
	c.birth = time.Now().Add(-(time.Duration(uint64(1)<<32)*time.Millisecond + 50*time.Millisecond))
	c.Write([]byte{1})
	stamp := uint32(time.Since(c.birth)/time.Millisecond) - 10
	c.input([]record{{token: 4, code: ackCode, edge: 100, next: 0, stamp: stamp, numbers: []uint32{0}}})
	if len(c.out) != 0 {
		t.Fatal("ACK wrap did not retire packet")
	}
	if c.smooth <= 0 || c.smooth > 50*time.Millisecond {
		t.Fatal("timestamp wrap RTT", c.smooth)
	}
	for n := uint32(0); n < 400; n++ {
		c.ack[n] = receipt{stamp: n}
	}
	c.ackDirty = true
	packets := handedPackets(c, time.Now())
	acks := 0
	seen := map[uint32]bool{}
	for _, packet := range packets {
		if len(packet) > 576 {
			t.Fatal("ACK over MTU")
		}
		rows, e := decode(packet, 1460)
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range rows {
			if r.code != ackCode {
				continue
			}
			acks++
			if len(r.numbers) > 128 {
				t.Fatal("ACK batch too large")
			}
			for _, n := range r.numbers {
				if seen[n] {
					t.Fatal("duplicate compressed ACK")
				}
				seen[n] = true
			}
		}
	}
	if acks != 4 || len(seen) != 400 {
		t.Fatal("ACK compression lost entries", acks, len(seen))
	}
}
