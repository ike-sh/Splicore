package wireguardendpoint

import (
	"io"
	"net"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// memoryTUN is exclusively wired between an official Device and its own Core
// IP stack. It has no public packet-injection API. Each direction is bounded.
type memoryTUN struct {
	mtu       int
	decrypted chan []byte
	plaintext chan []byte
	events    chan tun.Event
	done      chan struct{}
	once      sync.Once
}

func newMemoryTUN(mtu int) *memoryTUN {
	t := &memoryTUN{mtu: mtu, decrypted: make(chan []byte, 256), plaintext: make(chan []byte, 256), events: make(chan tun.Event), done: make(chan struct{})}
	return t
}
func (t *memoryTUN) File() *os.File           { return nil }
func (t *memoryTUN) Name() (string, error)    { return "splicore-wireguard", nil }
func (t *memoryTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *memoryTUN) BatchSize() int           { return 1 }
func (t *memoryTUN) Events() <-chan tun.Event { return t.events }
func (t *memoryTUN) Close() error             { t.once.Do(func() { close(t.done); close(t.events) }); return nil }

func (t *memoryTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.done:
		return 0, net.ErrClosed
	default:
	}
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-t.done:
		return 0, net.ErrClosed
	case packet := <-t.plaintext:
		if len(bufs[0])-offset < len(packet) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}

func (t *memoryTUN) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.done:
		return 0, net.ErrClosed
	default:
	}
	for i, b := range bufs {
		if offset < 0 || offset > len(b) {
			return i, io.ErrShortBuffer
		}
		if len(b)-offset > t.mtu {
			return i, io.ErrShortBuffer
		}
		select {
		case <-t.done:
			return i, net.ErrClosed
		default:
		}
		packet := append([]byte(nil), b[offset:]...)
		select {
		case <-t.done:
			return i, net.ErrClosed
		case t.decrypted <- packet:
		}
	}
	return len(bufs), nil
}

// stackDevice is the opposite orientation of the same in-memory TUN.
// Interrupt closes the exact bridge object and wakes both engines' I/O.
type stackDevice struct{ tun *memoryTUN }

func (d stackDevice) Start() error     { return nil }
func (d stackDevice) Close() error     { return d.tun.Close() }
func (d stackDevice) Interrupt() error { return d.tun.Close() }
func (d stackDevice) Read(b []byte) (int, error) {
	select {
	case <-d.tun.done:
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-d.tun.done:
		return 0, net.ErrClosed
	case packet := <-d.tun.decrypted:
		if len(b) < len(packet) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, packet), nil
	}
}

func (d stackDevice) Write(b []byte) (int, error) {
	select {
	case <-d.tun.done:
		return 0, net.ErrClosed
	default:
	}
	if len(b) > d.tun.mtu {
		return 0, io.ErrShortBuffer
	}
	packet := append([]byte(nil), b...)
	select {
	case <-d.tun.done:
		return 0, net.ErrClosed
	case d.tun.plaintext <- packet:
		return len(b), nil
	}
}

// drain is called only after both the official Device and Core stack joined.
func (t *memoryTUN) drain() {
	for len(t.decrypted) > 0 {
		<-t.decrypted
	}
	for len(t.plaintext) > 0 {
		<-t.plaintext
	}
}
