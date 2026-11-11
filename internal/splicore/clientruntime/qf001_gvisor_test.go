//go:build with_gvisor

package clientruntime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Like NativeTun's iovec storage, scratch belongs to the device, not a call.
// hold represents a syscall still consuming that storage. No payload may be
// reused or released until WritePacket returns.
type qfPacketDevice struct {
	hold         <-chan struct{}
	scratch      [64]byte
	active, peak atomic.Int32
	calls        atomic.Int32
	mu           sync.Mutex
	packets      [][]byte
	writeResult  func(*stack.PacketBuffer) (int, error)
}

func (d *qfPacketDevice) WritePacket(p *stack.PacketBuffer) (int, error) {
	active := d.active.Add(1)
	defer d.active.Add(-1)
	for old := d.peak.Load(); active > old && !d.peak.CompareAndSwap(old, active); old = d.peak.Load() {
	}
	d.calls.Add(1)
	if d.writeResult != nil {
		return d.writeResult(p)
	}
	var n int
	for _, part := range p.AsSlices() {
		n += copy(d.scratch[n:], part)
	}
	if d.hold != nil {
		<-d.hold
	}
	d.mu.Lock()
	d.packets = append(d.packets, bytes.Clone(d.scratch[:n]))
	d.mu.Unlock()
	return n, nil
}

func qfPacket(value byte) *stack.PacketBuffer {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Repeat([]byte{value}, 64))})
}

func TestQF001ConcurrentWritePacket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		device := &qfPacketDevice{hold: release}
		writer := newPreparedEndpoint(device, nil, stack.NICOptions{})
		start := make(chan struct{})
		var workers sync.WaitGroup
		for i := range 32 {
			workers.Go(func() {
				p := qfPacket(byte(i))
				defer p.DecRef()
				<-start
				if n, err := writer.WritePacket(p); n != 64 || err != nil {
					t.Errorf("packet %d: n=%d err=%v", i, n, err)
				}
			})
		}
		close(start)
		// All callers are now blocked either behind the owner or in the held
		// syscall. With the old promoted method, all 32 enter device scratch.
		synctest.Wait()
		if device.calls.Load() != 1 || device.active.Load() != 1 {
			t.Errorf("device scratch has simultaneous owners: calls=%d active=%d", device.calls.Load(), device.active.Load())
		}
		close(release)
		workers.Wait()
		if device.peak.Load() != 1 || len(device.packets) != 32 {
			t.Fatalf("writer ownership/integrity: peak=%d packets=%d", device.peak.Load(), len(device.packets))
		}
		seen := map[byte]bool{}
		for _, payload := range device.packets {
			if len(payload) != 64 || !bytes.Equal(payload, bytes.Repeat(payload[:1], 64)) || seen[payload[0]] {
				t.Fatalf("payload overwritten, truncated or duplicated: %x", payload)
			}
			seen[payload[0]] = true
		}
	})
}

type qfStack struct {
	onClose func() error
	closed  atomic.Int32
}

func (s *qfStack) Close() error { s.closed.Add(1); return s.onClose() }

func TestQF001WriteAndShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		device := &qfPacketDevice{hold: release}
		writer := newPreparedEndpoint(device, nil, stack.NICOptions{})
		underlying := &qfStack{onClose: func() error {
			if device.active.Load() != 0 {
				return fmt.Errorf("closed stack with active syscall")
			}
			return nil
		}}
		s := &ownedStack{Closer: underlying, writer: writer}
		activeDone := make(chan struct{})
		go func() {
			defer close(activeDone)
			p := qfPacket(1)
			defer p.DecRef()
			if n, err := writer.WritePacket(p); n != 64 || err != nil {
				t.Errorf("admitted write failed: %d %v", n, err)
			}
		}()
		synctest.Wait()
		var queued sync.WaitGroup
		for range 16 {
			queued.Go(func() {
				p := qfPacket(2)
				defer p.DecRef()
				if n, err := writer.WritePacket(p); n != 0 || !errors.Is(err, os.ErrClosed) {
					t.Errorf("queued write after stop: %d %v", n, err)
				}
			})
		}
		synctest.Wait()
		closed := make(chan error, 1)
		go func() { closed <- s.Close() }()
		synctest.Wait()
		if !writer.stopped.Load() || underlying.closed.Load() != 0 {
			t.Error("shutdown must reject admission and drain the outstanding syscall first")
		}
		close(release)
		<-activeDone
		queued.Wait()
		if err := <-closed; err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil || underlying.closed.Load() != 1 || device.calls.Load() != 1 {
			t.Fatalf("shutdown ownership: err=%v closes=%d calls=%d", err, underlying.closed.Load(), device.calls.Load())
		}
		if _, err := writer.WritePacket(nil); !errors.Is(err, os.ErrClosed) {
			t.Fatal("stopped writer touched retired packet/device", err)
		}
	})
}

func TestQF001IndependentDeviceWriters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		devices := []*qfPacketDevice{{hold: release}, {hold: release}}
		var workers sync.WaitGroup
		for _, d := range devices {
			writer := newPreparedEndpoint(d, nil, stack.NICOptions{})
			workers.Go(func() {
				p := qfPacket(3)
				defer p.DecRef()
				if _, err := writer.WritePacket(p); err != nil {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		for _, d := range devices {
			if d.active.Load() != 1 {
				t.Error("unrelated device serialized behind another device")
			}
		}
		close(release)
		workers.Wait()
	})
}

func TestQF001WriteDuringGenerationRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		m := New()
		first := hardeningCandidate(t, m)
		if err := first.Activate(); err != nil {
			t.Fatal(err)
		}
		gen := m.acquire()
		_, session := m.registerFlow(context.Background(), "", nil, nil)
		release := make(chan struct{})
		device := &qfPacketDevice{hold: release}
		writer := newPreparedEndpoint(device, nil, stack.NICOptions{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer m.finishFlow(session, gen)
			p := qfPacket(4)
			defer p.DecRef()
			if _, err := writer.WritePacket(p); err != nil {
				t.Error(err)
			}
		}()
		synctest.Wait()
		second := hardeningCandidate(t, m)
		if err := second.Activate(); err != nil {
			t.Fatal(err)
		}
		if gen.refs.Load() != 1 || len(m.underlay.Status().Generations) != 2 {
			t.Error("generation retired before active packet write finished")
		}
		close(release)
		<-done
		if gen.refs.Load() != 0 || len(m.underlay.Status().Generations) != 1 {
			t.Error("retired generation ownership retained after write")
		}
		if err := m.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestQF001WriteErrorContract(t *testing.T) {
	for _, want := range []error{os.ErrClosed, context.Canceled, errors.New("write failure"), errors.New("invalid packet")} {
		device := &qfPacketDevice{writeResult: func(*stack.PacketBuffer) (int, error) { return 7, want }}
		writer := newPreparedEndpoint(device, nil, stack.NICOptions{})
		p := qfPacket(5)
		n, err := writer.WritePacket(p)
		p.DecRef()
		if n != 7 || err != want {
			t.Fatalf("changed backend result: %d %v", n, err)
		}
		// An error must return scratch ownership for the next call.
		p = qfPacket(6)
		_, err = writer.WritePacket(p)
		p.DecRef()
		if err != want || device.calls.Load() != 2 {
			t.Fatal("write failure retained ownership")
		}
	}
}

func BenchmarkQF001WritePacket(b *testing.B) {
	for _, parallel := range []bool{false, true} {
		b.Run(fmt.Sprint("parallel=", parallel), func(b *testing.B) {
			device := &qfPacketDevice{writeResult: func(p *stack.PacketBuffer) (int, error) { return p.Size(), nil }}
			writer := newPreparedEndpoint(device, nil, stack.NICOptions{})
			b.ReportAllocs()
			if parallel {
				b.RunParallel(func(pb *testing.PB) {
					p := qfPacket(7)
					defer p.DecRef()
					for pb.Next() {
						if _, err := writer.WritePacket(p); err != nil {
							b.Fatal(err)
						}
					}
				})
			} else {
				p := qfPacket(7)
				defer p.DecRef()
				b.ResetTimer()
				for b.Loop() {
					if _, err := writer.WritePacket(p); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
