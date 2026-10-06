package backend

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/packetio"
)

func TestPacketWriteLifecycleAndSibling(t *testing.T) {
	for _, mode := range []string{"close", "future", "past", "parent", "clear"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			entered, release := make(chan struct{}, 2), make(chan struct{})
			w := packetio.NewWriter(parent, func([]byte) error {
				entered <- struct{}{}
				select {
				case <-release:
					return nil
				case <-parent.Done():
					return net.ErrClosed
				}
			})
			defer w.Wait()
			defer cancel()
			p := newPacket(parent, nil, 1, w.Send)
			sibling := newPacket(parent, nil, 2, w.Send)
			defer p.Close()
			defer sibling.Close()
			result := make(chan error, 2)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
			go func() { _, err := p.WriteTo([]byte("blocked"), addr); result <- err }()
			<-entered
			if mode != "clear" {
				go func() { _, err := p.WriteTo([]byte("admission"), addr); result <- err }()
			}
			want := net.ErrClosed
			switch mode {
			case "close":
				p.Close()
			case "parent":
				cancel()
			case "future":
				want = os.ErrDeadlineExceeded
				p.SetWriteDeadline(time.Now().Add(time.Millisecond))
			case "past":
				want = os.ErrDeadlineExceeded
				p.SetWriteDeadline(time.Now().Add(-time.Second))
			case "clear":
				p.SetWriteDeadline(time.Now().Add(time.Hour))
				p.SetWriteDeadline(time.Now().Add(time.Minute))
				p.SetWriteDeadline(time.Now().Add(2 * time.Hour))
				p.SetWriteDeadline(time.Time{})
				close(release)
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
					t.Fatal("pending write survived cancellation")
				}
			}
			if mode == "parent" {
				w.Wait()
				return
			}
			p.Close()
			if _, err := p.WriteTo([]byte("closed"), addr); !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
			close(release)
			if _, err := sibling.WriteTo([]byte("sibling"), addr); err != nil {
				t.Fatal(err)
			}
		})
	}
}
