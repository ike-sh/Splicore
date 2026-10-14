package mkcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type flight struct {
	body     []byte
	due      time.Time
	attempts uint32
	pending  bool
}
type receipt struct {
	stamp uint32
	due   time.Time
}
type clockPolicy struct{ idle, drain, end, ping time.Duration }

var normalClock = clockPolicy{30 * time.Second, 15 * time.Second, 8 * time.Second, 3 * time.Second}

// Conn has one timer owner and one mutex for bounded logical state. Socket I/O
// happens outside that mutex; blocked application I/O waits on replaceable
// notifications so concurrent deadline changes and Close always wake it.
type Conn struct {
	mu                                                     sync.Mutex
	releaseMu                                              sync.Mutex
	config                                                 cfg.MKCP
	token                                                  uint16
	local, peer                                            net.Addr
	send                                                   func([]byte) error
	writer                                                 *packetWriter
	owned                                                  net.Conn
	readerDone                                             chan struct{}
	joined                                                 chan struct{}
	done                                                   chan struct{}
	changed                                                chan struct{}
	clock                                                  clockPolicy
	birth, lastInput, lastControl, lastACK                 time.Time
	closeAt, endAt                                         time.Time
	readDeadline, writeDeadline                            time.Time
	localClosed, peerClosing, remoteEOF, stopped, released bool
	terminal                                               error
	onRelease                                              func()
	onStopped                                              func()
	detached                                               bool
	sendNext, recvNext, remoteEdge                         uint32
	order                                                  []uint32
	out                                                    map[uint32]*flight
	in                                                     map[uint32][]byte
	ack                                                    map[uint32]receipt
	readChunk                                              []byte
	ackDirty                                               bool
	ackVersion                                             uint64
	ackPending                                             bool
	controlPending                                         int
	rto, smooth, spread                                    time.Duration
	budget                                                 uint32
}

func newConn(m cfg.MKCP, token uint16, local, peer net.Addr, send func([]byte) error, release func()) *Conn {
	now := time.Now()
	return &Conn{config: m, token: token, local: local, peer: peer, send: send, onRelease: release, clock: normalClock,
		birth: now, lastInput: now, lastControl: now.Add(-normalClock.ping), rto: 100 * time.Millisecond, budget: m.SendSlots(),
		joined: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{}),
		out: map[uint32]*flight{}, in: map[uint32][]byte{}, ack: map[uint32]receipt{}, remoteEdge: 32}
}

// Dial uses only the caller's approved UDP dialer. Logical opening has no
// artificial handshake; the upper protocol performs its ordinary admission.
func Dial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), address string, m cfg.MKCP) (*Conn, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := dial(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	var random [2]byte
	if _, err = rand.Read(random[:]); err != nil {
		raw.Close()
		return nil, err
	}
	c := newConn(m, binary.BigEndian.Uint16(random[:]), raw.LocalAddr(), raw.RemoteAddr(), func(b []byte) error {
		if e := raw.SetWriteDeadline(time.Now().Add(socketWriteLimit)); e != nil {
			return e
		}
		n, e := raw.Write(b)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		return e
	}, nil)
	c.owned = raw
	c.readerDone = make(chan struct{})
	go func() {
		defer close(c.readerDone)
		b := make([]byte, 65536)
		for {
			n, e := raw.Read(b)
			if e != nil {
				c.transportError(e)
				return
			}
			rows, e := decode(b[:n], 1460)
			if e != nil {
				continue
			}
			c.input(rows)
		}
	}()
	go c.run()
	if err = ctx.Err(); err != nil {
		c.abort(err)
		<-c.joined
		return nil, err
	}
	return c, nil
}

func (c *Conn) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Conn) firstLocked() uint32 {
	for _, n := range c.order {
		if c.out[n] != nil {
			return n
		}
	}
	return c.sendNext
}
func (c *Conn) pruneLocked() {
	kept := c.order[:0]
	for _, n := range c.order {
		if c.out[n] != nil {
			kept = append(kept, n)
		}
	}
	c.order = kept
}
func (c *Conn) cumulativeLocked(next uint32) {
	if earlier(c.sendNext, next) {
		return
	}
	for n := range c.out {
		if earlier(n, next) {
			delete(c.out, n)
		}
	}
	c.pruneLocked()
}
func (c *Conn) clearReceiptsLocked(floor uint32) {
	for n := range c.ack {
		if earlier(n, floor) {
			delete(c.ack, n)
		}
	}
}
func (c *Conn) sampleLocked(sample time.Duration) {
	if sample < 0 || sample > 10*time.Second {
		return
	}
	if sample < time.Millisecond {
		sample = time.Millisecond
	}
	if c.smooth == 0 {
		c.smooth = sample
		c.spread = sample / 2
	} else {
		delta := sample - c.smooth
		if delta < 0 {
			delta = -delta
		}
		c.spread = (c.spread*3 + delta) / 4
		c.smooth = (c.smooth*7 + sample) / 8
	}
	c.rto = c.smooth + 4*c.spread
	minimum := time.Duration(c.config.TTI) * time.Millisecond
	if c.rto < minimum {
		c.rto = minimum
	}
	if c.rto > 10*time.Second {
		c.rto = 10 * time.Second
	}
}
func (c *Conn) input(rows []record) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped || c.remoteEOF {
		return
	}
	for _, r := range rows {
		if r.token != c.token {
			return
		}
	}
	c.lastInput = now
	for _, r := range rows {
		if c.remoteEOF {
			break
		}
		if r.closing {
			c.peerClosing = true
		}
		switch r.code {
		case dataCode:
			c.clearReceiptsLocked(r.floor)
			if c.localClosed {
				c.ackDirty = true
				c.ackVersion++
				continue
			}
			if within(r.sequence, c.recvNext, c.config.ReceiveSlots()) {
				if _, exists := c.in[r.sequence]; !exists {
					c.in[r.sequence] = append([]byte(nil), r.data...)
				}
				c.ack[r.sequence] = receipt{stamp: r.stamp}
				c.ackDirty = true
				c.ackVersion++
			} else if earlier(r.sequence, c.recvNext) {
				c.ackDirty = true
				c.ackVersion++
			}
		case ackCode:
			if earlier(c.sendNext, r.next) || r.edge-r.next > 1<<20 {
				continue
			}
			if earlier(c.remoteEdge, r.edge) {
				c.remoteEdge = r.edge
			}
			c.cumulativeLocked(r.next)
			var newest uint32
			progress := false
			for _, n := range r.numbers {
				if f := c.out[n]; f != nil {
					delete(c.out, n)
					if !progress || earlier(newest, n) {
						newest = n
					}
					progress = true
				}
			}
			if progress {
				elapsed := uint32(now.Sub(c.birth)/time.Millisecond) - r.stamp
				if elapsed < 10000 {
					c.sampleLocked(time.Duration(elapsed) * time.Millisecond)
				}
				// Later selective progress accelerates the missing earlier packet.
				for n, f := range c.out {
					if earlier(n, newest) && f.attempts > 0 && f.due.After(now.Add(c.rto/3)) {
						f.due = now.Add(c.rto / 3)
					}
				}
			}
			c.pruneLocked()
		case helloCode, endCode:
			c.cumulativeLocked(r.next)
			c.clearReceiptsLocked(r.floor)
			if r.code == endCode {
				c.remoteEOF = true
				c.peerClosing = true
				clear(c.out)
				c.order = nil
			}
		}
	}
	c.signalLocked()
}

func (c *Conn) stopLocked(err error) {
	if c.stopped {
		return
	}
	c.stopped = true
	c.terminal = err
	clear(c.out)
	c.order = nil
	clear(c.ack)
	if c.writer != nil {
		c.writer.purgeLocked(c)
	}
	close(c.done)
	c.signalLocked()
}
func (c *Conn) abort(err error) {
	c.mu.Lock()
	clear(c.in)
	c.readChunk = nil
	c.stopLocked(err)
	c.mu.Unlock()
	c.releaseIfDone()
}

// Socket teardown is not an application Abort. Once normal EOF is established,
// even an expected private reader close error must leave the readable tail owned
// by the stream. Live hard errors retain the existing destructive contract.
func (c *Conn) transportError(err error) {
	c.mu.Lock()
	if !c.stopped {
		if c.remoteEOF {
			c.stopLocked(io.EOF)
		} else {
			clear(c.in)
			c.readChunk = nil
			c.stopLocked(err)
		}
	}
	c.mu.Unlock()
	c.releaseIfDone()
}
func (c *Conn) releaseIfDone() {
	// Done must also join callbacks already claimed by a concurrent reader or
	// writer; their flags alone do not prove reservation/demux cleanup finished.
	c.releaseMu.Lock()
	defer c.releaseMu.Unlock()
	c.mu.Lock()
	var retired, release func()
	if c.stopped && !c.detached {
		c.detached = true
		retired = c.onStopped
	}
	if c.stopped && !c.released && (c.localClosed || len(c.in) == 0 && len(c.readChunk) == 0) {
		c.released = true
		release = c.onRelease
	}
	c.mu.Unlock()
	if retired != nil {
		retired()
	}
	if release != nil {
		release()
	}
}

func (c *Conn) tick(now time.Time) []*output {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return nil
	}
	base := record{token: c.token, closing: c.localClosed, floor: c.firstLocked(), next: c.recvNext, interval: uint32(c.rto / time.Millisecond)}
	var packets []*output
	control := func(code byte) {
		r := base
		r.code = code
		packets = append(packets, &output{conn: c, record: r})
		c.controlPending++
	}
	if c.remoteEOF {
		if c.endAt.IsZero() {
			c.endAt = now
		}
		if now.Sub(c.endAt) >= c.clock.end {
			c.stopLocked(io.EOF)
			return nil
		}
		// Queue rejection leaves the reply eligible. Successful handoff stops
		// the transport in finish; blocked output cannot extend the end bound.
		if c.controlPending == 0 {
			control(endCode)
		}
		return packets
	}
	if now.Sub(c.lastInput) >= c.clock.idle {
		clear(c.in)
		c.readChunk = nil
		c.stopLocked(os.ErrDeadlineExceeded)
		return nil
	}
	if c.localClosed && (len(c.out) == 0 || now.Sub(c.closeAt) >= c.clock.drain) {
		if c.endAt.IsZero() {
			c.endAt = now
		}
		if now.Sub(c.endAt) >= c.clock.end {
			c.stopLocked(net.ErrClosed)
			return nil
		}
		if c.controlPending == 0 && (now.Sub(c.lastControl) >= 100*time.Millisecond || now.Equal(c.endAt)) {
			control(endCode)
		}
		return packets
	}
	// ACK bookkeeping persists only until the sender advertises its first
	// outstanding sequence; repeat ACK loss never permanently stalls the sender.
	keys := make([]uint32, 0, len(c.ack))
	stamp := uint32(0)
	for n, a := range c.ack {
		if c.ackDirty || !now.Before(a.due) {
			keys = append(keys, n)
			if earlier(stamp, a.stamp) {
				stamp = a.stamp
			}
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i]-c.recvNext < keys[j]-c.recvNext })
	count := (int(c.config.MTU) - 17) / 4
	if count > 128 {
		count = 128
	}
	// Selective receipts disappear when the application consumes them. Repeat
	// the cumulative/window advertisement as well: losing its final empty ACK
	// must not strand a sender at the old receive edge with nothing to retry.
	ackInterval := c.rto
	if ackInterval < 100*time.Millisecond {
		ackInterval = 100 * time.Millisecond
	}
	repeatWindow := !c.lastACK.IsZero() && now.Sub(c.lastACK) >= ackInterval
	if !c.ackPending && (len(keys) > 0 || c.ackDirty || repeatWindow) {
		group := &ackBatch{version: c.ackVersion}
		c.ackPending = true
		for start := 0; start < len(keys) || start == 0; start += count {
			end := start + count
			if end > len(keys) {
				end = len(keys)
			}
			r := record{token: c.token, code: ackCode, closing: c.localClosed, edge: c.recvNext + c.config.ReceiveSlots(), next: c.recvNext, stamp: stamp, numbers: append([]uint32(nil), keys[start:end]...)}
			packets = append(packets, &output{conn: c, record: r, ack: group})
			group.remaining++
			if end == len(keys) {
				break
			}
		}
	}
	budget := uint64(c.budget) * uint64(c.config.CWNDMultiplier)
	if budget > uint64(c.config.QueueSlots()) {
		budget = uint64(c.config.QueueSlots())
	}
	group := &dataBatch{}
	for _, n := range c.order {
		f := c.out[n]
		if f == nil || f.pending || now.Before(f.due) || !earlier(n, c.remoteEdge) {
			continue
		}
		if uint64(group.remaining) >= budget {
			break
		}
		r := base
		r.code = dataCode
		r.sequence = n
		r.data = f.body
		packets = append(packets, &output{conn: c, record: r, flight: f, data: group})
		f.pending = true
		group.remaining++
	}
	if c.controlPending == 0 && now.Sub(c.lastControl) >= c.clock.ping {
		control(helloCode)
	}
	return packets
}

func (c *Conn) run() {
	c.mu.Lock()
	privateWriter := c.writer == nil
	if privateWriter {
		c.writer = newPacketWriter()
	}
	c.mu.Unlock()
	defer func() {
		c.releaseIfDone() // Session retirement never waits for a socket write.
		if privateWriter {
			c.mu.Lock()
			graceful := c.terminal == io.EOF
			c.mu.Unlock()
			if !graceful && c.owned != nil {
				c.owned.Close() // Interrupt a blocked private Write/Read.
			}
			c.writer.close()
			<-c.writer.joined // EOF reply only; socket writes have a hard deadline.
		}
		if c.owned != nil {
			c.owned.Close()
			<-c.readerDone
		}
		c.releaseIfDone()
		close(c.joined)
	}()
	ticker := time.NewTicker(time.Duration(c.config.TTI) * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case now := <-ticker.C:
			c.advance(now)
		}
	}
}

// advance performs lifecycle work and nonblocking queue admission only.
func (c *Conn) advance(now time.Time) {
	for _, p := range c.tick(now) {
		c.writer.offer(p)
	}
	c.releaseIfDone()
}

func wait(ch <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		<-ch
		return nil
	}
	timeout := time.NewTimer(time.Until(deadline))
	defer timeout.Stop()
	select {
	case <-ch:
		return nil
	case <-timeout.C:
		return os.ErrDeadlineExceeded
	}
}
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if c.localClosed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if len(c.readChunk) == 0 {
			if p := c.in[c.recvNext]; p != nil {
				c.readChunk = p
				delete(c.in, c.recvNext)
				delete(c.ack, c.recvNext)
				c.recvNext++
				c.ackDirty = true
				c.ackVersion++
			}
		}
		if len(c.readChunk) > 0 {
			n := copy(b, c.readChunk)
			c.readChunk = c.readChunk[n:]
			c.signalLocked()
			c.mu.Unlock()
			c.releaseIfDone()
			return n, nil
		}
		if c.remoteEOF || c.stopped {
			err := c.terminal
			if err == nil {
				err = io.EOF
			}
			clear(c.in)
			c.mu.Unlock()
			c.releaseIfDone()
			return 0, err
		}
		ch, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		if err := wait(ch, deadline); err != nil {
			return 0, err
		}
	}
}
func (c *Conn) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		c.mu.Lock()
		if c.localClosed || c.peerClosing || c.stopped {
			c.mu.Unlock()
			return written, net.ErrClosed
		}
		if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		if uint32(len(c.out)) < c.config.QueueSlots() {
			n := int(c.config.MTU) - dataHeader
			if n > len(b) {
				n = len(b)
			}
			c.out[c.sendNext] = &flight{body: append([]byte(nil), b[:n]...)}
			c.order = append(c.order, c.sendNext)
			c.sendNext++
			c.mu.Unlock()
			written += n
			b = b[n:]
			continue
		}
		ch, deadline := c.changed, c.writeDeadline
		c.mu.Unlock()
		if err := wait(ch, deadline); err != nil {
			return written, err
		}
	}
	return written, nil
}
func (c *Conn) Close() error {
	c.mu.Lock()
	if !c.localClosed {
		c.localClosed = true
		c.closeAt = time.Now()
		clear(c.in)
		c.readChunk = nil
		c.signalLocked()
	}
	c.mu.Unlock()
	c.releaseIfDone()
	return nil
}
func (c *Conn) LocalAddr() net.Addr  { return c.local }
func (c *Conn) RemoteAddr() net.Addr { return c.peer }
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.signalLocked()
	c.mu.Unlock()
	return nil
}

// Done is a physical owner barrier, useful to callers retiring a private socket.
func (c *Conn) Done() <-chan struct{} { return c.joined }

// Abort retires a failed admission immediately and joins the private socket
// owner. Published streams use Close for bounded graceful draining.
func (c *Conn) Abort(err error) { c.abort(err); <-c.joined }
