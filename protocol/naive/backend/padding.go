// Package backend implements Naive CONNECT and padding using generic HTTP libraries.
package backend

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

const FirstPaddings = 8
const MaxPayload = 65535
const MaxPadding = 255

// PaddingConn counts records independently in each direction, per CONNECT stream.
// The writer emits zero padding; the decoder accepts arbitrary padding bytes.
type PaddingConn struct {
	net.Conn
	rmu, wmu                       sync.Mutex
	rng                            io.Reader
	reads, writes                  int
	header                         [3]byte
	headerN, dataLeft, paddingLeft int
	readingRecord                  bool
}

func Padded(conn net.Conn) *PaddingConn { return paddedWithRandom(conn, rand.Reader) }
func paddedWithRandom(conn net.Conn, rng io.Reader) *PaddingConn {
	return &PaddingConn{Conn: conn, rng: rng}
}
func (c *PaddingConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for c.reads < FirstPaddings {
		if !c.readingRecord {
			for c.headerN < len(c.header) {
				n, err := c.Conn.Read(c.header[c.headerN:])
				c.headerN += n
				if err != nil {
					if err == io.EOF && c.headerN != 0 {
						err = io.ErrUnexpectedEOF
					}
					if c.headerN == len(c.header) {
						c.dataLeft = int(binary.BigEndian.Uint16(c.header[:2]))
						c.paddingLeft = int(c.header[2])
						c.readingRecord = true
					}
					return 0, err
				}
				if n == 0 {
					return 0, io.ErrNoProgress
				}
			}
			c.dataLeft = int(binary.BigEndian.Uint16(c.header[:2]))
			c.paddingLeft = int(c.header[2])
			c.readingRecord = true
		}
		if c.dataLeft > 0 {
			limit := min(len(p), c.dataLeft)
			n, err := c.Conn.Read(p[:limit])
			c.dataLeft -= n
			if err == io.EOF && (c.dataLeft > 0 || c.paddingLeft > 0) {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		var discard [MaxPadding]byte
		for c.paddingLeft > 0 {
			n, err := c.Conn.Read(discard[:c.paddingLeft])
			c.paddingLeft -= n
			if err != nil {
				if err == io.EOF && c.paddingLeft > 0 {
					err = io.ErrUnexpectedEOF
				}
				if c.paddingLeft == 0 {
					c.finishRecord()
				}
				return 0, err
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}
		c.finishRecord()
	}
	return c.Conn.Read(p)
}
func (c *PaddingConn) finishRecord() { c.reads++; c.headerN = 0; c.readingRecord = false }
func writeAll(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func (c *PaddingConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 && c.writes < FirstPaddings {
		length := min(len(p), MaxPayload)
		var random [1]byte
		if _, err := io.ReadFull(c.rng, random[:]); err != nil {
			return total, err
		}
		frame := make([]byte, 3+length+int(random[0]))
		binary.BigEndian.PutUint16(frame[:2], uint16(length))
		frame[2] = random[0]
		copy(frame[3:], p[:length])
		n, err := writeAll(c.Conn, frame)
		if err != nil {
			// A partially emitted record cannot be retried as a fresh record.
			_ = c.Conn.Close()
			return total + max(0, min(length, n-3)), err
		}
		total += length
		p = p[length:]
		c.writes++
	}
	if len(p) > 0 {
		n, err := c.Conn.Write(p)
		return total + n, err
	}
	return total, nil
}
func (c *PaddingConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return c.Conn.Close()
}
