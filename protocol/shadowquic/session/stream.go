//go:build with_quic

package session

import (
	"net"
	"sync"
	"sync/atomic"

	quic "github.com/metacubex/jls-quic-go"
)

type stream struct {
	*quic.Stream
	conn       *quic.Conn
	once       sync.Once
	finished   atomic.Bool
	afterClose func()
}

func (s *stream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }
func (s *stream) CloseWrite() error    { s.finished.Store(true); return s.Stream.Close() }
func (s *stream) Close() error {
	s.once.Do(func() {
		s.CancelRead(0)
		if !s.finished.Load() {
			s.CancelWrite(0)
		}
		_ = s.Stream.Close()
		if s.afterClose != nil {
			s.afterClose()
		}
	})
	return nil
}
