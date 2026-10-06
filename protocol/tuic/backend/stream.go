package backend

import (
	"github.com/quic-go/quic-go"
	"net"
	"sync"
	"sync/atomic"
)

// CloseWrite emits FIN and keeps the receive side and transport alive. Close
// interrupts pending reads/writes and releases the private client transport.
type Stream struct {
	*quic.Stream
	q          *quic.Conn
	afterClose func()
	once       sync.Once
	writeEnded atomic.Bool
}

func (s *Stream) LocalAddr() net.Addr  { return s.q.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.q.RemoteAddr() }
func (s *Stream) CloseWrite() error    { s.writeEnded.Store(true); return s.Stream.Close() }
func (s *Stream) Close() error {
	s.once.Do(func() {
		s.CancelRead(0)
		if !s.writeEnded.Load() {
			s.CancelWrite(0)
		}
		_ = s.Stream.Close()
		if s.afterClose != nil {
			s.afterClose()
		}
	})
	return nil
}
