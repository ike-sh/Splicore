// Package traffic counts plaintext payload and session ownership at the owned
// protocol boundary. It has no wire buffers, socket creation or protocol types.
package traffic

import (
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

type Counter struct {
	Upload, Download, Sessions, Active             atomic.Int64
	TCPSessions, TCPActive, UDPSessions, UDPActive atomic.Int64
}

func (m *Counter) Snapshot() ports.Stats {
	return ports.Stats{Upload: m.Upload.Load(), Download: m.Download.Load(), Sessions: m.Sessions.Load(), Active: m.Active.Load(), TCPSessions: m.TCPSessions.Load(), TCPActive: m.TCPActive.Load(), UDPSessions: m.UDPSessions.Load(), UDPActive: m.UDPActive.Load()}
}

// Open records one logical session. The returned release is safe to call from
// both relay directions and shutdown; counters never own or retain buffers.
func Open(tcp bool, counters ...*Counter) func() {
	owned := slices.Clone(counters)
	for _, m := range owned {
		if m == nil {
			continue
		}
		m.Sessions.Add(1)
		m.Active.Add(1)
		if tcp {
			m.TCPSessions.Add(1)
			m.TCPActive.Add(1)
		} else {
			m.UDPSessions.Add(1)
			m.UDPActive.Add(1)
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for _, m := range owned {
				if m == nil {
					continue
				}
				m.Active.Add(-1)
				if tcp {
					m.TCPActive.Add(-1)
				} else {
					m.UDPActive.Add(-1)
				}
			}
		})
	}
}

func CountUpload(n int, counters ...*Counter) {
	if n > 0 {
		for _, m := range counters {
			if m != nil {
				m.Upload.Add(int64(n))
			}
		}
	}
}
func CountDownload(n int, counters ...*Counter) {
	if n > 0 {
		for _, m := range counters {
			if m != nil {
				m.Download.Add(int64(n))
			}
		}
	}
}

// Conn is a server-side plaintext boundary: Read counts upload and Write counts
// download. It deliberately implements neither ReaderFrom nor WriterTo, so
// io.Copy cannot bypass accounting. The caller owns the underlying connection.
func Conn(c net.Conn, counters ...*Counter) net.Conn {
	owned := slices.Clone(counters)
	return &countConn{Conn: c, counters: owned, release: Open(true, owned...)}
}

type countConn struct {
	net.Conn
	counters []*Counter
	release  func()
}

func (c *countConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	CountUpload(n, c.counters...)
	return n, e
}
func (c *countConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	CountDownload(n, c.counters...)
	return n, e
}
func (c *countConn) Close() error { c.release(); return c.Conn.Close() }
func (c *countConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return errors.ErrUnsupported
}
func (c *countConn) CloseRead() error {
	if h, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return h.CloseRead()
	}
	return errors.ErrUnsupported
}

func Packet(c net.PacketConn, counters ...*Counter) net.PacketConn {
	owned := slices.Clone(counters)
	return &countPacket{PacketConn: c, counters: owned, release: Open(false, owned...)}
}

type countPacket struct {
	net.PacketConn
	counters []*Counter
	release  func()
}

func (p *countPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	CountUpload(n, p.counters...)
	return n, a, e
}
func (p *countPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	n, e := p.PacketConn.WriteTo(b, a)
	CountDownload(n, p.counters...)
	return n, e
}
func (p *countPacket) Close() error { p.release(); return p.PacketConn.Close() }
