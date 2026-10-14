package mkcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func connBarrier(t *testing.T, c *Conn, ready func() bool) {
	t.Helper()
	timeout := time.NewTimer(4 * time.Second)
	defer timeout.Stop()
	for {
		c.mu.Lock()
		ok, changed := ready(), c.changed
		c.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-changed:
		case <-timeout.C:
			t.Fatal("connection state barrier not reached")
		}
	}
}
func buffered(c *Conn) int {
	n := len(c.readChunk)
	for _, p := range c.in {
		n += len(p)
	}
	return n
}

// The actual Dial/private UDP reader accepts every byte before EOF. Selective
// ACKs are a packet barrier, and Done proves socket/reader/writer teardown before
// the application drains its retained tail. Timeouts only bound failed tests.
func TestDialNormalEOFRetainsAcceptedTail(t *testing.T) {
	for _, spec := range []struct {
		name                            string
		size, chunk, prefix             int
		reorder, closeLocal, concurrent bool
	}{
		{"unread", 4097, 4097, 0, false, false, false},
		{"one-byte", 4097, 1, 0, false, false, false},
		{"large-tail", 129 * 1024, 4096, 0, false, false, false},
		{"empty", 0, 1, 0, false, false, false},
		{"partial-read", 4097, 31, 13, false, false, false},
		{"reorder-resolves", 4097, 19, 0, true, false, false},
		{"local-close", 4097, 1, 0, false, true, false},
		{"EOF-vs-read", 65537, 1024, 0, false, false, true},
	} {
		t.Run(spec.name, func(t *testing.T) {
			m := tuning()
			server, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			d := net.Dialer{}
			c, err := Dial(context.Background(), d.DialContext, server.LocalAddr().String(), m)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Abort(net.ErrClosed)
			want := payload(spec.size, 47)
			const segmentSize = 1000
			segments := (len(want) + segmentSize - 1) / segmentSize
			writeSegment := func(n int) {
				end := (n + 1) * segmentSize
				if end > len(want) {
					end = len(want)
				}
				p := encode(record{token: c.token, code: dataCode, sequence: uint32(n), data: want[n*segmentSize : end], stamp: uint32(n + 1)})
				if _, e := server.WriteTo(p, c.LocalAddr()); e != nil {
					t.Fatal(e)
				}
			}
			if spec.reorder {
				for n := 1; n < segments; n++ {
					writeSegment(n)
				}
				connBarrier(t, c, func() bool { return buffered(c) == len(want)-segmentSize && c.in[0] == nil })
				writeSegment(0)
			} else {
				for n := 0; n < segments; n++ {
					writeSegment(n)
				}
			}
			connBarrier(t, c, func() bool { return buffered(c) == len(want) })
			// Explicitly prove the peer has received ACKs for the admitted bytes.
			acked := map[uint32]bool{}
			server.SetReadDeadline(time.Now().Add(4 * time.Second))
			buf := make([]byte, 65536)
			for len(acked) < segments {
				n, _, e := server.ReadFrom(buf)
				if e != nil {
					t.Fatal(e)
				}
				rows, e := decode(buf[:n], 1460)
				if e != nil {
					t.Fatal(e)
				}
				for _, r := range rows {
					if r.code == ackCode {
						for _, seq := range r.numbers {
							acked[seq] = true
						}
					}
				}
			}
			got := make([]byte, spec.prefix)
			if spec.prefix > 0 {
				if _, e := io.ReadFull(c, got); e != nil {
					t.Fatal(e)
				}
			}
			var drain chan []byte
			if spec.concurrent {
				drain = make(chan []byte, 1)
				go func() {
					b, e := io.ReadAll(c)
					if e != nil {
						t.Error(e)
					}
					drain <- b
				}()
			}
			if _, e := server.WriteTo(encode(record{token: c.token, code: endCode}), c.LocalAddr()); e != nil {
				t.Fatal(e)
			}
			waitDone(t, c.Done())
			waitDone(t, c.readerDone)
			if _, e := c.owned.Write([]byte{1}); !errors.Is(e, net.ErrClosed) {
				t.Fatal("private socket remains open", e)
			}
			c.input([]record{{token: c.token, code: dataCode, sequence: uint32(segments), data: []byte("after EOF")}})
			if spec.closeLocal {
				c.Close()
				if _, e := c.Read(buf); !errors.Is(e, net.ErrClosed) {
					t.Fatal(e)
				}
				c.mu.Lock()
				n := buffered(c)
				c.mu.Unlock()
				if n != 0 {
					t.Fatal("local Close retained tail")
				}
				t.Logf("accepted=%d local_discard=%d owner_joined=true", len(want), len(want))
				return
			}
			if drain != nil {
				got = <-drain
			} else {
				chunk := make([]byte, spec.chunk)
				for {
					n, e := c.Read(chunk)
					got = append(got, chunk[:n]...)
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("accepted=%d read=%d payload mismatch", len(want), len(got))
			}
			if n, e := c.Read(buf); n != 0 || e != io.EOF {
				t.Fatal("tail did not end at EOF", n, e)
			}
			c.mu.Lock()
			left := buffered(c)
			c.mu.Unlock()
			if left != 0 {
				t.Fatal("drained tail retained", left)
			}
			t.Logf("accepted=%d acked_segments=%d application_read=%d sha256=%x missing=0 duplicate=0 reordered=0 discarded=0 reader_writer_socket_joined=true", len(want), len(acked), len(got), sha256.Sum256(got))
		})
	}
}

func TestEOFAndLocalCloseReleaseOnce(t *testing.T) {
	var releases atomic.Int32
	c := newConn(tuning(), 1, nil, nil, func([]byte) error { return nil }, func() { releases.Add(1) })
	go c.run()
	c.input([]record{{token: 1, code: dataCode, data: payload(1000, 3)}})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); <-start; c.input([]record{{token: 1, code: endCode}}) }()
	go func() { defer wg.Done(); <-start; c.Close() }()
	close(start)
	wg.Wait()
	// Either interleaving has local destructive Close semantics.
	c.transportError(net.ErrClosed)
	waitDone(t, c.Done())
	c.abort(net.ErrClosed)
	c.Close()
	if releases.Load() != 1 {
		t.Fatal("release count", releases.Load())
	}
}

func TestRemoteEOFRejectsLaterRecords(t *testing.T) {
	c := newConn(tuning(), 1, nil, nil, nil, nil)
	c.input([]record{{token: 1, code: dataCode, data: []byte("a")}, {token: 1, code: endCode}, {token: 1, code: dataCode, sequence: 1, data: []byte("b")}})
	c.input([]record{{token: 1, code: dataCode, sequence: 1, data: []byte("c")}})
	if buffered(c) != 1 {
		t.Fatal("future bytes admitted after EOF")
	}
	c.transportError(net.ErrClosed) // A teardown race before the next tick.
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "a" || c.terminal != io.EOF {
		t.Fatal("EOF state", got, err)
	}
}

// Real UDP :0 ownership is preserved. Only output is held at an explicit
// barrier; Close interrupts that barrier and the underlying actual socket.
type blockedPacket struct {
	net.PacketConn
	entered         chan struct{}
	release         chan struct{}
	closed          chan struct{}
	once, writeOnce sync.Once
	fail            error
	deadlines       atomic.Int32
}

func blockUDP(t *testing.T) *blockedPacket {
	t.Helper()
	p, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	b := &blockedPacket{PacketConn: p, entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	t.Cleanup(func() { b.Close() })
	return b
}
func (b *blockedPacket) WriteTo(p []byte, a net.Addr) (int, error) {
	b.writeOnce.Do(func() { close(b.entered) })
	select {
	case <-b.closed:
		return 0, net.ErrClosed
	case <-b.release:
	}
	if b.fail != nil {
		return 0, b.fail
	}
	return b.PacketConn.WriteTo(p, a)
}
func (b *blockedPacket) SetWriteDeadline(d time.Time) error {
	b.deadlines.Add(1)
	return b.PacketConn.SetWriteDeadline(d)
}
func (b *blockedPacket) Close() error {
	b.once.Do(func() { close(b.closed); b.PacketConn.Close() })
	return nil
}

func blockedSession(t *testing.T, l *Listener, token uint16) *Conn {
	t.Helper()
	peer, e := net.Dial("udp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { peer.Close() })
	if _, e = peer.Write(encode(record{token: token, code: dataCode, data: []byte{1}})); e != nil {
		t.Fatal(e)
	}
	raw, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	c := raw.(*Conn)
	connBarrier(t, c, func() bool { return buffered(c) == 1 })
	return c
}

func TestBlockedUDPWriterIndependentTimers(t *testing.T) {
	for _, mode := range []string{"idle", "dead-peer", "local-close", "remote-EOF", "multi-session", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			p := blockUDP(t)
			m := tuning()
			m.MaxSendingWindow = m.MTU
			l, e := NewListener(p, m)
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			c := blockedSession(t, l, 1)
			waitDone(t, p.entered)
			if p.deadlines.Load() == 0 {
				t.Fatal("carrier write lacked deadline")
			}
			c.SetReadDeadline(time.Now().Add(-time.Second))
			if _, e := c.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal(e)
			}
			c.SetReadDeadline(time.Time{})
			// Stream write deadlines remain effective while both the physical
			// writer and the reliable send queue are blocked.
			if _, e := c.Write(make([]byte, int(m.MTU)-dataHeader)); e != nil {
				t.Fatal(e)
			}
			write := make(chan error, 1)
			go func() { _, e := c.Write([]byte{2}); write <- e }()
			c.SetWriteDeadline(time.Now().Add(-time.Second))
			if e := <-write; !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal("blocked stream write deadline", e)
			}
			c.SetWriteDeadline(time.Time{})
			if mode == "multi-session" {
				other := blockedSession(t, l, 2)
				other.advance(time.Now().Add(normalClock.idle))
				waitDone(t, other.Done())
				if l.ActiveSessions() != 1 {
					t.Fatal("sibling timer starved")
				}
			}
			if mode == "remote-EOF" {
				c.input([]record{{token: c.token, code: endCode}})
				now := time.Now()
				c.advance(now)
				c.advance(now.Add(normalClock.end))
				// Transport expires with the writer still blocked. Its valid tail
				// stays readable and only then releases the held reservation.
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, []byte{1}) {
					t.Fatal("blocked EOF drain", got, err)
				}
			} else if mode == "local-close" {
				c.Close()
				now := time.Now().Add(normalClock.drain)
				c.advance(now)
				c.advance(now.Add(normalClock.end))
			} else if mode == "shutdown" {
				l.Close()
			} else {
				c.advance(time.Now().Add(normalClock.idle))
			}
			waitDone(t, c.Done())
			l.mu.Lock()
			active, held, reserved := len(l.sessions), len(l.held), l.reserved
			l.mu.Unlock()
			if active != 0 || held != 0 || reserved != 0 {
				t.Fatal("blocked output retained session resources", active, held, reserved)
			}
			if mode != "shutdown" {
				select {
				case <-l.writer.joined:
					t.Fatal("worker joined before socket close")
				default:
				}
				select {
				case <-p.closed:
					t.Fatal("session expiry closed sibling socket")
				default:
				}
			}
			l.Close()
			waitDone(t, l.writer.joined)
			if len(queuedOutputs(l.writer)) != 0 {
				t.Fatal("writer did not drain cancelled output")
			}
			t.Logf("write_entered=true timer_triggered=true active=0 held=0 reserved=0 expiry_before_writer_unblock=%v output_worker_joined=true", mode != "shutdown")
		})
	}
}

func TestOutputQueueFullAndHandoffAccounting(t *testing.T) {
	m := tuning()
	m.CWNDMultiplier = 1024
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c := newConn(m, 1, nil, nil, func([]byte) error { once.Do(func() { close(entered) }); <-release; return nil }, nil)
	w := newPacketWriter()
	c.writer = w
	defer func() { c.abort(net.ErrClosed); w.close(); close(release); waitDone(t, w.joined) }()
	c.remoteEdge = 1000
	c.Write(payload(320*(int(m.MTU)-dataHeader), 3))
	plans := c.tick(time.Now())
	w.offer(plans[0])
	waitDone(t, entered)
	for _, p := range plans[1:] {
		w.offer(p)
	}
	if len(queuedOutputs(w)) != outputQueueLimit {
		t.Fatal("output queue bound", len(queuedOutputs(w)))
	}
	c.mu.Lock()
	unscheduled := 0
	for _, f := range c.out {
		if f.attempts != 0 || !f.due.IsZero() {
			t.Fatal("queued output counted as UDP success")
		}
		if !f.pending {
			unscheduled++
		}
	}
	c.mu.Unlock()
	if unscheduled == 0 {
		t.Fatal("queue full not exercised")
	}
	// More scheduler work while the physical writer is still held cannot wait.
	c.advance(time.Now().Add(time.Second))
	c.mu.Lock()
	for _, f := range c.out {
		if f.attempts != 0 || !f.due.IsZero() {
			t.Fatal("queue rejection advanced RTO")
		}
	}
	c.mu.Unlock()
	c.abort(net.ErrClosed)
	w.close()
	if len(queuedOutputs(w)) != 0 {
		t.Fatal("closed session retained queued output")
	}
	t.Logf("capacity=%d observed_full=%d after_abort=%d unscheduled=%d attempts=0 due_unchanged=true timer_progress=true", outputQueueLimit, outputQueueLimit, len(queuedOutputs(w)), unscheduled)
}

func TestOutputRetryACKAndControlAccounting(t *testing.T) {
	c := newConn(tuning(), 1, nil, nil, nil, nil)
	c.Write([]byte{1})
	c.input([]record{{token: 1, code: dataCode, data: []byte{2}, stamp: 1}})
	now := time.Now()
	for _, p := range c.tick(now) {
		p.finish(false, now)
	}
	if c.out[0].attempts != 0 || !c.out[0].due.IsZero() || !c.lastACK.IsZero() || !c.ackDirty {
		t.Fatal("rejected plans committed accounting")
	}
	packets := handedPackets(c, now)
	if len(packets) != 3 || c.out[0].attempts != 1 || c.out[0].due != now.Add(c.rto) || c.lastACK != now || c.ackDirty {
		t.Fatal("successful handoff accounting")
	}
	due := c.out[0].due
	for _, p := range c.tick(due) {
		p.finish(false, due)
	}
	if c.out[0].attempts != 1 || c.out[0].due != due {
		t.Fatal("unsent retry counted")
	}
	handedPackets(c, due)
	if c.out[0].attempts != 2 || c.out[0].due != due.Add(c.rto) {
		t.Fatal("successful retry not counted")
	}
	// A queued old ACK cannot clear a newer receipt/window update.
	c.input([]record{{token: 1, code: dataCode, sequence: 1, data: []byte{3}, stamp: 2}})
	plans := c.tick(due.Add(c.rto))
	c.input([]record{{token: 1, code: dataCode, sequence: 2, data: []byte{4}, stamp: 3}})
	for _, p := range plans {
		p.finish(true, due.Add(c.rto))
	}
	if !c.ackDirty || !c.ack[2].due.IsZero() {
		t.Fatal("stale ACK completion overwrote receipt")
	}
}

func TestUDPWriterFatalErrorAndHardReceiveContract(t *testing.T) {
	p := blockUDP(t)
	want := errors.New("controlled carrier failure")
	p.fail = want
	close(p.release)
	l, e := NewListener(p, tuning())
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	// Publish the connection via queue first, so fatal output cannot race Accept.
	peer, e := net.Dial("udp4", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	peer.Write(encode(record{token: 1, code: dataCode, data: []byte{1}}))
	var c *Conn
	select {
	case c = <-l.queue:
	case <-time.After(4 * time.Second):
		t.Fatal("admission barrier")
	}
	waitDone(t, c.Done())
	if _, e := c.Read(make([]byte, 1)); !errors.Is(e, want) {
		t.Fatal("hard error contract", e)
	}
	if l.ActiveSessions() != 0 || l.reserved != 0 {
		t.Fatal("fatal write retained resources")
	}
	l.Close()
	waitDone(t, l.writer.joined)
}

func TestRetiredTokenReservationBoundaries(t *testing.T) {
	for _, initial := range []int{0, 1, 4090, 4095, 4096} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			m := tuning()
			m.UplinkCapacity = 0
			m.DownlinkCapacity = 0
			m.MaxSendingWindow = m.MTU
			l := &Listener{config: m, sessions: map[peerKey]*Conn{}, held: map[*Conn]bool{}, retired: map[peerKey]time.Time{}}
			now := time.Unix(1700000000, 0)
			for i := 0; i < initial; i++ {
				l.retired[peerKey{"old", uint16(i)}] = now.Add(retiredTokenTTL)
			}
			admitted := 0
			keys := []peerKey{}
			// This is exactly the historical 4095 + 64 path, with retirement
			// capacity now reserved before each of the 64 admission attempts.
			for i := 0; i < 64; i++ {
				key := peerKey{"new", uint16(i)}
				if l.canAdmitLocked(key) {
					c := newConn(m, key.token, nil, nil, nil, nil)
					l.sessions[key] = c
					l.held[c] = true
					l.reserved += l.config.PayloadBound()
					admitted++
					keys = append(keys, key)
				}
			}
			maximum := initial
			var wg sync.WaitGroup
			for _, key := range keys {
				wg.Add(1)
				go func(key peerKey) {
					defer wg.Done()
					l.mu.Lock()
					defer l.mu.Unlock()
					c := l.sessions[key]
					l.retireLocked(key, now)
					delete(l.held, c)
					l.reserved -= l.config.PayloadBound()
					l.retireLocked(key, now.Add(time.Second))
					if len(l.retired) > maximum {
						maximum = len(l.retired)
					}
					if len(l.retired)+len(l.sessions) > retiredTokenLimit {
						t.Error("retirement invariant")
					}
					if l.retired[key] != now.Add(retiredTokenTTL) {
						t.Error("duplicate refreshed TTL")
					}
				}(key)
			}
			wg.Wait()
			want := 64
			if retiredTokenLimit-initial < want {
				want = retiredTokenLimit - initial
			}
			if admitted != want || maximum > 4096 || len(l.retired) != initial+want {
				t.Fatal("boundary", initial, admitted, maximum)
			}
			key := peerKey{"new", 65}
			if initial >= 4090 && l.canAdmitLocked(key) {
				t.Fatal("4097th reservation admitted")
			}
			for _, old := range keys {
				if l.canAdmitLocked(old) {
					t.Fatal("late packet admitted during TTL")
				}
			}
			l.expireRetiredLocked(now.Add(retiredTokenTTL - time.Nanosecond))
			if len(l.retired) != initial+want {
				t.Fatal("early expiry")
			}
			l.expireRetiredLocked(now.Add(retiredTokenTTL))
			if len(l.retired) != 0 || !l.canAdmitLocked(key) {
				t.Fatal("exact expiry did not reopen capacity")
			}
			// Replace an expired token with a new session; old expiry must not
			// erase the new generation's later retirement.
			l.sessions[key] = newConn(tuning(), key.token, nil, nil, nil, nil)
			l.retireLocked(key, now.Add(retiredTokenTTL))
			l.expireRetiredLocked(now.Add(retiredTokenTTL + time.Second))
			if len(l.retired) != 1 {
				t.Fatal("replacement expiry")
			}
			t.Logf("initial=%d attempted=64 admitted=%d rejected=%d maximum=%d cap=4096 unexpired_evictions=0 expiry_and_duplicate=PASS", initial, admitted, 64-admitted, maximum)
		})
	}
}
