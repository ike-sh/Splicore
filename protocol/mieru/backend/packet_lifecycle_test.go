package backend

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/clientio"
)

// Model the pinned SDK's contextless deadline-snapshot blocking surface. Close
// interrupts only this logical session, never a sibling's multiplexed underlay.
type snapshotPacket struct {
	net.PacketConn
	entered chan []byte
	closed  chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (p *snapshotPacket) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.entered <- b
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	case <-p.resume:
		return len(b), nil
	}
}
func (p *snapshotPacket) Close() error                    { p.once.Do(func() { close(p.closed) }); return nil }
func (p *snapshotPacket) SetReadDeadline(time.Time) error { return nil }

func TestMieruPacketWriteLifecycle(t *testing.T) {
	for _, mode := range []string{"close", "future", "past", "clear", "parent"} {
		t.Run(mode, func(t *testing.T) {
			owner := clientio.New()
			defer owner.Close()
			raw := &snapshotPacket{entered: make(chan []byte, 2), closed: make(chan struct{}), resume: make(chan struct{})}
			target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
			p := newMieruPacket(raw, target)
			owned, err := owner.Packet(p)
			if err != nil {
				t.Fatal(err)
			}
			defer owned.Close()
			result := make(chan error, 2)
			scratch := []byte("owned-frame")
			go func() { _, err := owned.WriteTo(scratch, nil); result <- err }()
			frame := <-raw.entered
			if mode != "clear" {
				go func() { _, err := owned.WriteTo([]byte("waiting"), nil); result <- err }()
			}
			want := net.ErrClosed
			switch mode {
			case "close":
				owned.Close()
			case "parent":
				owner.Close()
			case "past":
				want = os.ErrDeadlineExceeded
				owned.SetWriteDeadline(time.Now().Add(-time.Second))
			case "future":
				want = os.ErrDeadlineExceeded
				owned.SetWriteDeadline(time.Now().Add(time.Millisecond))
			case "clear":
				owned.SetDeadline(time.Now().Add(time.Hour))
				owned.SetWriteDeadline(time.Now().Add(time.Minute))
				owned.SetWriteDeadline(time.Now().Add(2 * time.Hour))
				owned.SetWriteDeadline(time.Time{})
				close(raw.resume)
				select {
				case err := <-result:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("clear stalled")
				}
				return
			}
			for range 2 {
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("%v want %v", err, want)
					}
				case <-time.After(time.Second):
					t.Fatal("SDK snapshot blocked child wait")
				}
			}
			copy(scratch, "new-scratch")
			if string(frame) != "owned-frame" {
				t.Fatal("borrowed frame retained")
			}
			owned.Close()
			p.writer.Wait()
			if _, err := owned.WriteTo([]byte("closed"), nil); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			if mode != "parent" {
				other := &snapshotPacket{entered: make(chan []byte, 1), closed: make(chan struct{}), resume: make(chan struct{})}
				close(other.resume)
				sibling, err := owner.Packet(newMieruPacket(other, target))
				if err != nil {
					t.Fatal(err)
				}
				defer sibling.Close()
				if _, err := sibling.WriteTo([]byte("sibling"), nil); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestMieruParentCloseDeadlineRace(t *testing.T) {
	for range 100 {
		owner := clientio.New()
		raw := &snapshotPacket{entered: make(chan []byte, 1), closed: make(chan struct{}), resume: make(chan struct{})}
		p := newMieruPacket(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
		owned, err := owner.Packet(p)
		if err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { _, err := owned.WriteTo([]byte("pending"), nil); result <- err }()
		<-raw.entered
		var wg sync.WaitGroup
		wg.Go(func() { owned.Close() })
		wg.Go(owner.Close)
		wg.Go(func() { owned.SetWriteDeadline(time.Now().Add(-time.Second)); owned.SetWriteDeadline(time.Time{}) })
		wg.Wait()
		select {
		case err := <-result:
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close race stalled")
		}
		p.writer.Wait()
	}
}
