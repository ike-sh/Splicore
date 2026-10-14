package mkcp

import (
	"io"
	"sync"
	"time"
)

const outputQueueLimit = 128
const socketWriteLimit = 2 * time.Second

type ackBatch struct {
	remaining int
	version   uint64
	failed    bool
}
type dataBatch struct {
	remaining  int
	sent, lost uint64
}

// Output plans hold immutable, bounded segment bodies. pending is queue
// ownership only, never a transmission count. finish commits successful UDP
// handoff, or makes rejected/failed plans eligible again without advancing RTO.
type output struct {
	conn   *Conn
	record record
	flight *flight
	ack    *ackBatch
	data   *dataBatch
}

func (p *output) prepare(now time.Time) ([]byte, bool) {
	c := p.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped && !(c.terminal == io.EOF && p.record.code == endCode) {
		return nil, false
	}
	if p.flight != nil {
		if c.out[p.record.sequence] != p.flight {
			return nil, false
		}
		p.record.stamp = uint32(now.Sub(c.birth) / time.Millisecond)
	}
	return encode(p.record), true
}

func (p *output) finish(success bool, now time.Time) {
	c := p.conn
	c.mu.Lock()
	defer c.mu.Unlock()
	p.finishLocked(success, now)
}

// The producer, queue cancellation owner or dequeued writer finishes a plan
// exactly once. Its connection mutex protects accounting, not socket progress.
// Clearing the plan also releases references held by a completed tick snapshot.
func (p *output) finishLocked(success bool, now time.Time) {
	c := p.conn
	defer c.signalLocked()
	defer func() { *p = output{} }()
	if f := p.flight; f != nil {
		f.pending = false
		if success && !c.stopped && c.out[p.record.sequence] == f {
			if f.attempts > 0 {
				p.data.lost++
			}
			p.data.sent++
			f.attempts++
			f.due = now.Add(c.rto)
		}
		if c.stopped {
			f.body = nil
		}
		p.data.remaining--
		if p.data.remaining == 0 && p.data.sent > 0 {
			if p.data.lost*100 >= p.data.sent*15 {
				c.budget = c.budget * 3 / 4
			} else if p.data.lost*100 <= p.data.sent*5 {
				c.budget += c.budget / 4
			}
			if c.budget < 8 {
				c.budget = 8
			}
			if c.budget > c.config.SendSlots() {
				c.budget = c.config.SendSlots()
			}
		}
	} else if g := p.ack; g != nil {
		g.remaining--
		if !success {
			g.failed = true
		}
		if success && !c.stopped {
			c.lastACK = now
			// An input refresh or application read invalidates the snapshot.
			if c.ackVersion == g.version {
				retry := c.rto / 2
				if retry < 20*time.Millisecond {
					retry = 20 * time.Millisecond
				}
				for _, n := range p.record.numbers {
					if a, ok := c.ack[n]; ok {
						a.due = now.Add(retry)
						c.ack[n] = a
					}
				}
			}
		}
		if g.remaining == 0 {
			c.ackPending = false
			if !g.failed && c.ackVersion == g.version {
				c.ackDirty = false
			}
		}
	} else {
		c.controlPending--
		if success {
			c.lastControl = now
			if p.record.code == endCode && c.remoteEOF {
				c.stopLocked(io.EOF)
			}
		}
	}
}

// Each UDP socket has one output worker. The timer never waits for queue space.
// A fixed ring permits stable session-specific removal without waiting for the
// socket worker. Only a dequeued plan belongs to that worker. No queue lock is
// held during connection callbacks, accounting or socket I/O.
type packetWriter struct {
	mu           sync.Mutex
	queue        [outputQueueLimit]*output
	head, size   int
	ready        chan struct{}
	done, joined chan struct{}
	closed       bool
}

func newPacketWriter() *packetWriter {
	w := &packetWriter{ready: make(chan struct{}, 1), done: make(chan struct{}), joined: make(chan struct{})}
	go w.run()
	return w
}
func (w *packetWriter) offer(p *output) {
	c := p.conn
	// Admission and stop/purge serialize under the same lifetime mutex. An
	// already prepared plan cannot enter the queue after stop has finalized.
	c.mu.Lock()
	w.mu.Lock()
	if !w.closed && !c.stopped && w.size < outputQueueLimit {
		w.queue[(w.head+w.size)%outputQueueLimit] = p
		w.size++
		select {
		case w.ready <- struct{}{}:
		default:
		}
		w.mu.Unlock()
		c.mu.Unlock()
		return
	}
	w.mu.Unlock()
	p.finishLocked(false, time.Now())
	c.mu.Unlock()
}

// purgeLocked requires c.mu. Conn.mu -> writer.mu is the only nested order;
// dequeue releases writer.mu before it accesses a connection. At most 128
// entries are scanned. Relative order and every unused slot are preserved.
func (w *packetWriter) purgeLocked(c *Conn) {
	var removed [outputQueueLimit]*output
	w.mu.Lock()
	kept, dropped := 0, 0
	for i := 0; i < w.size; i++ {
		index := (w.head + i) % outputQueueLimit
		p := w.queue[index]
		w.queue[index] = nil
		if p.conn == c {
			removed[dropped] = p
			dropped++
		} else {
			w.queue[(w.head+kept)%outputQueueLimit] = p
			kept++
		}
	}
	w.size = kept
	if kept == 0 {
		w.head = 0
	}
	w.mu.Unlock()
	// Accounting and reference release are separate from queue mutation. The
	// worker cannot own any removed item, even when its current Write blocks.
	for i := 0; i < dropped; i++ {
		removed[i].finishLocked(false, time.Now())
		removed[i] = nil
	}
}

func (w *packetWriter) take() (*output, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size == 0 {
		return nil, w.closed
	}
	p := w.queue[w.head]
	w.queue[w.head] = nil
	w.head = (w.head + 1) % outputQueueLimit
	w.size--
	if w.size == 0 {
		w.head = 0
	}
	return p, w.closed
}
func (w *packetWriter) close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.done)
	}
	w.mu.Unlock()
}
func (w *packetWriter) write(p *output) {
	c := p.conn // The dequeued writer owns this plan until finish returns.
	b, ok := p.prepare(time.Now())
	var err error
	if ok {
		err = c.send(b)
	}
	p.finish(ok && err == nil, time.Now())
	if err != nil {
		c.transportError(err)
	}
}
func (w *packetWriter) run() {
	defer close(w.joined)
	for {
		p, closed := w.take()
		if p != nil {
			if closed && p.record.code != endCode {
				p.finish(false, time.Now())
			} else {
				w.write(p)
			}
			continue
		}
		if closed {
			return
		}
		select {
		case <-w.ready:
		case <-w.done:
		}
	}
}
