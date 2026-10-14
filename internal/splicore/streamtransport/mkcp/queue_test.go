package mkcp

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func queuedOutputs(w *packetWriter) []*output {
	w.mu.Lock()
	defer w.mu.Unlock()
	items := make([]*output, 0, w.size)
	for i := 0; i < w.size; i++ {
		items = append(items, w.queue[(w.head+i)%outputQueueLimit])
	}
	return items
}

func idleQueue() *packetWriter {
	return &packetWriter{ready: make(chan struct{}, 1), done: make(chan struct{}), joined: make(chan struct{})}
}

func queueConnection(w *packetWriter, token uint16) *Conn {
	c := newConn(tuning(), token, nil, nil, func([]byte) error { return nil }, nil)
	c.writer = w
	c.lastControl = c.birth
	return c
}

// The tracker owns only the plan pointer and a digest, never the payload slice.
// It observes logical ownership release by inspecting every retaining field;
// there is no production buffer pool or GC-based lifetime assertion.
type trackedQueueBuffer struct {
	plan     *output
	digest   [32]byte
	released bool
}
type queueBuffers struct {
	items               []*trackedQueueBuffer
	allocated, released int
}

func (b *queueBuffers) plan(c *Conn, sequence uint32) *output {
	body := payload(1332, int(sequence)+17)
	f := &flight{body: body, pending: true}
	c.mu.Lock()
	if !c.stopped {
		c.out[sequence] = f
		c.order = append(c.order, sequence)
		if c.sendNext <= sequence {
			c.sendNext = sequence + 1
		}
	}
	c.mu.Unlock()
	p := &output{conn: c, record: record{token: c.token, code: dataCode, sequence: sequence, data: body}, flight: f, data: &dataBatch{remaining: 1}}
	b.items = append(b.items, &trackedQueueBuffer{plan: p, digest: sha256.Sum256(body)})
	b.allocated++
	return p
}
func emptyPlan(p *output) bool {
	return p.conn == nil && p.flight == nil && p.ack == nil && p.data == nil && p.record.data == nil && p.record.numbers == nil
}
func (b *queueBuffers) observeReleased(t *testing.T, want int) {
	t.Helper()
	for _, item := range b.items {
		if emptyPlan(item.plan) && !item.released {
			item.released = true
			b.released++
		}
		if item.released && !emptyPlan(item.plan) {
			t.Fatal("released ownership resurrected")
		}
	}
	if b.released != want {
		t.Fatal("tracked queue buffer release", b.allocated, b.released, want)
	}
}
func (b *queueBuffers) live(t *testing.T, p *output) {
	t.Helper()
	for _, item := range b.items {
		if item.plan == p {
			if item.released || p.conn == nil || p.flight == nil || sha256.Sum256(p.record.data) != item.digest {
				t.Fatal("live sibling payload changed")
			}
			return
		}
	}
	t.Fatal("untracked plan")
}
func queueHasNoReferences(t *testing.T, w *packetWriter, c *Conn) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range w.queue {
		if p != nil && p.conn == c {
			t.Fatal("closed session graph remains in queue")
		}
	}
}

func TestClosedSessionQueuePurgeWhileWriteBlocked(t *testing.T) {
	p := blockUDP(t)
	m := tuning()
	m.UplinkCapacity, m.DownlinkCapacity = 0, 0
	m.MaxSendingWindow = 256 * m.MTU
	l, e := NewListener(p, m)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c := blockedSession(t, l, 71)
	waitDone(t, p.entered)
	var buffers queueBuffers
	for i := uint32(0); i < 12; i++ {
		l.writer.offer(buffers.plan(c, i))
	}
	if len(queuedOutputs(l.writer)) < 12 {
		t.Fatal("reproduction did not retain twelve queued payloads")
	}
	for _, item := range buffers.items {
		buffers.live(t, item.plan)
	}
	c.abort(net.ErrClosed)
	waitDone(t, c.Done())
	queueHasNoReferences(t, l.writer, c)
	buffers.observeReleased(t, 12)
	if len(queuedOutputs(l.writer)) != 0 || l.ActiveSessions() != 0 {
		t.Fatal("terminal cleanup did not reclaim queue/demux")
	}
	select {
	case <-p.closed:
		t.Fatal("session purge closed the shared socket")
	default:
	}
	select {
	case <-l.writer.joined:
		t.Fatal("purge depended on physical writer completion")
	default:
	}
	// Reclaiming slots is real: a sibling can occupy all128 while the same
	// physical write remains blocked. The129th plan is rejected and cleared.
	sibling := queueConnection(l.writer, c.token)
	var other queueBuffers
	for i := uint32(0); i <= outputQueueLimit; i++ {
		l.writer.offer(other.plan(sibling, i))
	}
	if len(queuedOutputs(l.writer)) != outputQueueLimit {
		t.Fatal("purge left phantom occupied capacity")
	}
	other.observeReleased(t, 1)
	sibling.abort(net.ErrClosed)
	other.observeReleased(t, outputQueueLimit+1)
	queueHasNoReferences(t, l.writer, sibling)
	if len(queuedOutputs(l.writer)) != 0 {
		t.Fatal("sibling cleanup retained queue")
	}
	l.Close() // Interrupts the separately owned active write, then joins it.
	waitDone(t, l.writer.joined)
	t.Logf("allocated=%d released=%d queued_closed_refs=0 reclaimed_capacity=128 writer_unblock_required=false owner_loops=joined double_release=0", buffers.allocated+other.allocated, buffers.released+other.released)
}

func TestClosedSessionQueueCloseVsEnqueue(t *testing.T) {
	w := idleQueue()
	c := queueConnection(w, 7)
	var buffers queueBuffers
	ready, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	plan := buffers.plan(c, 0)
	go func() { close(ready); <-resume; w.offer(plan); close(done) }()
	<-ready
	c.abort(net.ErrClosed)
	// The producer still owns a prepared plan; the queue owns nothing. Resume
	// only after terminal cleanup, proving admission cannot cross that barrier.
	if len(queuedOutputs(w)) != 0 {
		t.Fatal("unexpected queued producer")
	}
	close(resume)
	<-done
	buffers.observeReleased(t, 1)
	w.offer(buffers.plan(c, 1)) // Allocation attempted after final close, too.
	buffers.observeReleased(t, 2)
	queueHasNoReferences(t, w, c)
	if len(queuedOutputs(w)) != 0 {
		t.Fatal("post-close enqueue succeeded")
	}
	w.close()
	go w.run()
	waitDone(t, w.joined)
	t.Log("before_enqueue_barrier=true close_finalized_first=true allocated=2 released=2 post_close_admitted=0 queued_closed_refs=0")
}

func TestClosedSessionQueueConcurrentEnqueue(t *testing.T) {
	for cycle := 0; cycle < 64; cycle++ {
		w := idleQueue()
		c := queueConnection(w, 1)
		var buffers queueBuffers
		start := make(chan struct{})
		var owners sync.WaitGroup
		for i := uint32(0); i < 32; i++ {
			p := buffers.plan(c, i)
			owners.Add(1)
			go func() { defer owners.Done(); <-start; w.offer(p) }()
		}
		owners.Add(1)
		go func() { defer owners.Done(); <-start; c.abort(net.ErrClosed) }()
		close(start)
		owners.Wait()
		buffers.observeReleased(t, 32)
		queueHasNoReferences(t, w, c)
		if len(queuedOutputs(w)) != 0 {
			t.Fatal("close/offer atomicity")
		}
		w.close()
		go w.run()
		waitDone(t, w.joined)
	}
	t.Log("cycles=64 competing_producers=32 allocated=2048 released=2048 queued_closed_refs=0 owner_loops=joined")
}

func TestClosedSessionQueueCloseVsDequeue(t *testing.T) {
	w := idleQueue()
	c := queueConnection(w, 9)
	var sends atomic.Int32
	c.send = func([]byte) error { sends.Add(1); return nil }
	var buffers queueBuffers
	first, second := buffers.plan(c, 0), buffers.plan(c, 1)
	w.offer(first)
	w.offer(second)
	dequeued, _ := w.take()
	if dequeued != first {
		t.Fatal("wrong dequeue order")
	}
	resume, done := make(chan struct{}), make(chan struct{})
	go func() { <-resume; w.write(dequeued); close(done) }()
	c.abort(net.ErrClosed)
	buffers.observeReleased(t, 1)
	buffers.live(t, first) // Already dequeued: distinct writer ownership.
	queueHasNoReferences(t, w, c)
	if len(queuedOutputs(w)) != 0 {
		t.Fatal("queued sibling of dequeued item retained")
	}
	close(resume)
	<-done
	buffers.observeReleased(t, 2)
	if sends.Load() != 0 {
		t.Fatal("stopped dequeued plan transmitted")
	}
	w.close()
	go w.run()
	waitDone(t, w.joined)
	t.Log("dequeue_before_close=true before_prepare_barrier=true queue_released=1 writer_owned=1 final_allocated=2 final_released=2 transmissions=0 double_release=0")
}

func TestClosedSessionQueueMixedStablePurge(t *testing.T) {
	w := idleQueue()
	// All sessions deliberately share the same wire token. Their lifetime
	// identity, including a wrapped ring head, must determine purge ownership.
	a, b, c := queueConnection(w, 13), queueConnection(w, 13), queueConnection(w, 13)
	w.head = outputQueueLimit - 3
	var buffers queueBuffers
	plans := []*output{buffers.plan(a, 0), buffers.plan(b, 0), buffers.plan(a, 1), buffers.plan(c, 0), buffers.plan(b, 1), buffers.plan(a, 2)}
	for _, p := range plans {
		w.offer(p)
	}
	b.Close()
	now := b.closeAt.Add(normalClock.drain)
	b.advance(now)
	b.advance(now.Add(normalClock.end))
	queueHasNoReferences(t, w, b)
	buffers.observeReleased(t, 2)
	want := []*output{plans[0], plans[2], plans[3], plans[5]}
	got := queuedOutputs(w)
	if len(got) != len(want) {
		t.Fatal("stable purge size", len(got))
	}
	for i, p := range got {
		if p != want[i] {
			t.Fatal("stable purge changed remaining order", i)
		}
		buffers.live(t, p)
	}
	// The ring has no hidden references in logically unused slots.
	w.mu.Lock()
	occupied := 0
	for _, p := range w.queue {
		if p != nil {
			occupied++
		}
	}
	w.mu.Unlock()
	if occupied != len(want) {
		t.Fatal("unused ring slot retained graph")
	}
	order := make(chan string, 4)
	for name, conn := range map[string]*Conn{"A": a, "C": c} {
		conn.send = func(packet []byte) error {
			rows, e := decode(packet, 1460)
			if e != nil {
				return e
			}
			order <- fmt.Sprintf("%s%d", name, rows[0].sequence+1)
			return nil
		}
	}
	go w.run()
	for _, expected := range []string{"A1", "A2", "C1", "A3"} {
		select {
		case actual := <-order:
			if actual != expected {
				t.Fatal("writer ordering", actual, expected)
			}
		case <-time.After(4 * time.Second):
			t.Fatal("writer lost wakeup")
		}
	}
	a.abort(net.ErrClosed)
	c.abort(net.ErrClosed)
	w.close()
	waitDone(t, w.joined)
	buffers.observeReleased(t, 6)
	t.Log("input=A1,B1,A2,C1,B2,A3 output=A1,A2,C1,A3 same_token=true ring_wrapped=true allocated=6 released=6 B_refs=0 sibling_payloads_unchanged=true")
}

func TestClosedSessionQueueActivityChurn256(t *testing.T) {
	p := blockUDP(t)
	m := tuning()
	m.UplinkCapacity, m.DownlinkCapacity = 0, 0
	m.MaxSendingWindow = 256 * m.MTU
	l, e := NewListener(p, m)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	seed := blockedSession(t, l, 90)
	waitDone(t, p.entered)
	seed.abort(net.ErrClosed)
	waitDone(t, seed.Done())
	l.owners.Wait()
	completed, allocated, released, maximumRetired := 0, 0, 0, 0
	outcomes := [6]int{}
	for cycle := 0; cycle < 256; cycle++ {
		mode := cycle % len(outcomes)
		if mode == 5 {
			// Actual lossy/retransmitted bidirectional queue activity, with
			// independent writers; both timer/output owners join before return.
			a, b, _, _ := pair(t, "data-loss", tuning())
			exchange(t, a, b, 4096, false)
			a.Close()
			b.Close()
			waitDone(t, a.Done())
			waitDone(t, b.Done())
			if len(queuedOutputs(a.writer))+len(queuedOutputs(b.writer)) != 0 {
				t.Fatal("loss/retransmit churn retained queue")
			}
		} else {
			c := blockedSession(t, l, uint16(cycle+100))
			var buffers queueBuffers
			n := 8
			if mode == 4 {
				n = 160
			}
			for i := 0; i < n; i++ {
				l.writer.offer(buffers.plan(c, uint32(i)))
			}
			if mode == 4 && len(queuedOutputs(l.writer)) != outputQueueLimit {
				t.Fatal("churn never reached full queue")
			}
			now := time.Now()
			switch mode {
			case 0, 4:
				c.Close()
				c.mu.Lock()
				closedAt := c.closeAt
				c.mu.Unlock()
				c.advance(closedAt.Add(normalClock.drain))
				c.advance(closedAt.Add(normalClock.drain + normalClock.end))
			case 1:
				c.input([]record{{token: c.token, code: endCode}})
				c.advance(now)
				c.advance(now.Add(normalClock.end))
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, []byte{1}) {
					t.Fatal("churn remote EOF tail", got, err)
				}
			case 2:
				c.Abort(net.ErrClosed)
			case 3:
				c.advance(now.Add(normalClock.idle))
			}
			waitDone(t, c.Done())
			l.owners.Wait()
			buffers.observeReleased(t, n)
			queueHasNoReferences(t, l.writer, c)
			allocated += buffers.allocated
			released += buffers.released
		}
		l.mu.Lock()
		active, held, reserved, retired := len(l.sessions), len(l.held), l.reserved, len(l.retired)
		l.mu.Unlock()
		if retired > maximumRetired {
			maximumRetired = retired
		}
		if active != 0 || held != 0 || reserved != 0 || retired > retiredTokenLimit || len(queuedOutputs(l.writer)) != 0 || allocated != released {
			t.Fatal("churn baseline", cycle, active, held, reserved, retired, allocated, released)
		}
		outcomes[mode]++
		completed++
	}
	l.Close()
	waitDone(t, l.writer.joined)
	if completed != 256 || allocated != released {
		t.Fatal("churn exact completion")
	}
	t.Logf("completed=256 normal_close=%d remote_close=%d cancel=%d blocked_idle=%d queue_full=%d loss_retransmit=%d allocated=%d released=%d active=0 held=0 reserved=0 queue=0 timers=0 retired_max=%d cap=4096 owner_loops=joined", outcomes[0], outcomes[1], outcomes[2], outcomes[3], outcomes[4], outcomes[5], allocated, released, maximumRetired)
}
