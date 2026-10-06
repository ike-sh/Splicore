package backend

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go"
	"github.com/ike-sh/Splicore/protocol/hysteria2/wire"
)

// Stream owns one bidirectional QUIC stream. Half-close sends FIN only; full
// Close interrupts both directions. A private client transport is released by
// afterClose only on full Close, preserving a response after upload EOF.
type Stream struct {
	*quic.Stream
	connection   *quic.Conn
	afterClose   func()
	once         sync.Once
	responseOnce sync.Once
	responseErr  error
	writeEnded   atomic.Bool
}

func (s *Stream) LocalAddr() net.Addr  { return s.connection.LocalAddr() }
func (s *Stream) RemoteAddr() net.Addr { return s.connection.RemoteAddr() }
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

// Reply is idempotent and precedes any payload writer at the native boundary.
func (s *Stream) Reply(ok bool) error {
	s.responseOnce.Do(func() { s.responseErr = wire.WriteResponse(s.Stream, ok) })
	return s.responseErr
}
