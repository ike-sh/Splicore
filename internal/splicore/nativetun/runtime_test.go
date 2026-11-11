package nativetun

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type testDispatcher struct {
	tcp, udp func(context.Context, net.Conn, netip.AddrPort, netip.AddrPort)
}

func (h testDispatcher) TCP(ctx context.Context, c net.Conn, s, d netip.AddrPort) {
	if h.tcp != nil {
		h.tcp(ctx, c, s, d)
	}
}
func (h testDispatcher) UDP(ctx context.Context, c net.Conn, s, d netip.AddrPort) {
	if h.udp != nil {
		h.udp(ctx, c, s, d)
	}
}

type testDevice struct {
	read        chan []byte
	interrupted chan struct{}
	once        sync.Once
	write       func([]byte) (int, error)
	closes      atomic.Int32
}

func newTestDevice() *testDevice {
	return &testDevice{read: make(chan []byte, 256), interrupted: make(chan struct{})}
}
func (d *testDevice) Start() error { return nil }
func (d *testDevice) Read(p []byte) (int, error) {
	select {
	case <-d.interrupted:
		return 0, net.ErrClosed
	case packet := <-d.read:
		return copy(p, packet), nil
	}
}
func (d *testDevice) Write(p []byte) (int, error) {
	if d.write != nil {
		return d.write(p)
	}
	return len(p), nil
}
func (d *testDevice) Interrupt() error { d.once.Do(func() { close(d.interrupted) }); return nil }
func (d *testDevice) Close() error     { d.closes.Add(1); return d.Interrupt() }

func TestWriterConcurrentOwnershipAndDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		var active, peak, calls atomic.Int32
		var scratch [64]byte
		var packets [][]byte
		device := newTestDevice()
		device.write = func(p []byte) (int, error) {
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
			}
			calls.Add(1)
			copy(scratch[:], p)
			<-hold
			packets = append(packets, bytes.Clone(scratch[:]))
			return len(p), nil
		}
		writer := newPacketWriter(device)
		var workers sync.WaitGroup
		for i := range 32 {
			workers.Go(func() {
				p := bytes.Repeat([]byte{byte(i)}, 64)
				n, err := writer.WritePacket(p)
				if n != 64 || err != nil {
					t.Errorf("write: %d %v", n, err)
				}
			})
		}
		synctest.Wait()
		if active.Load() != 1 || calls.Load() != 1 {
			t.Fatal("syscall scratch has multiple owners")
		}
		close(hold)
		workers.Wait()
		if peak.Load() != 1 || len(packets) != 32 {
			t.Fatal("ownership or packet loss")
		}
		seen := map[byte]bool{}
		for _, p := range packets {
			if seen[p[0]] || !bytes.Equal(p, bytes.Repeat(p[:1], 64)) {
				t.Fatal("packet corrupted")
			}
			seen[p[0]] = true
		}
		writer.reject()
		writer.drain()
		if _, err := writer.WritePacket([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
}

func TestWriterShutdownJoinsSyscall(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		device := newTestDevice()
		device.write = func(p []byte) (int, error) { <-hold; return len(p), nil }
		writer := newPacketWriter(device)
		activeDone := make(chan struct{})
		go func() { defer close(activeDone); _, _ = writer.WritePacket([]byte{1}) }()
		synctest.Wait()
		drained := make(chan struct{})
		go func() { writer.reject(); writer.drain(); close(drained) }()
		synctest.Wait()
		select {
		case <-drained:
			t.Fatal("returned with active syscall")
		default:
		}
		close(hold)
		<-activeDone
		<-drained
		if _, err := writer.WritePacket([]byte{2}); !errors.Is(err, net.ErrClosed) {
			t.Fatal(err)
		}
	})
}

func TestWriterErrorAndIndependentDevices(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		hold := make(chan struct{})
		d := newTestDevice()
		d.write = func(p []byte) (int, error) { <-hold; return len(p), nil }
		first := newPacketWriter(d)
		done := make(chan struct{})
		go func() { defer close(done); _, _ = first.WritePacket([]byte{1}) }()
		synctest.Wait()
		second := newTestDevice()
		second.write = func([]byte) (int, error) { return 0, nil }
		if _, err := newPacketWriter(second).WritePacket([]byte{2}); !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
		close(hold)
		<-done
	})
}

func TestStopBeforeStartAndConcurrentClose(t *testing.T) {
	device := newTestDevice()
	r, err := New(context.Background(), device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	var callers sync.WaitGroup
	for range 16 {
		callers.Go(func() {
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if r.State() != Stopped || device.closes.Load() != 0 {
		t.Fatal("runtime released host device")
	}
	if !errors.Is(r.Start(), ErrStarted) {
		t.Fatal("started stopped runtime")
	}
}

func TestCancelledStartAndInvalidOptions(t *testing.T) {
	device := newTestDevice()
	if _, err := New(context.Background(), device, Options{MTU: 1}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := New(ctx, device, Options{MTU: 1500, Dispatcher: testDispatcher{}})
	if err != nil {
		t.Fatal(err)
	}
	err = r.Start()
	if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrStarted) {
		t.Fatal(err)
	}
	_ = r.Close()
	if r.State() != Stopped && r.State() != Failed {
		t.Fatal(r.State())
	}
}
