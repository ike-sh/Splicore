package encryption

import (
	"crypto/cipher"
	"encoding/binary"
	"net"
)

// DirectConn is the pinned Vision transition target. Vision has already checked
// that the carried application stream is TLS 1.3. Its own records replace the
// VLESS AEAD records after command 2; outer transport security remains in place.
// Random mode retains the continuous record-header masks in both directions.
// Callers must drain the last decrypted record and serialize each direction.
func (c *Conn) DirectConn() net.Conn {
	if c.txMask == nil {
		return c.Conn
	}
	return &directConn{Conn: c.Conn, owner: c, tx: headerMask{mask: c.txMask}, rx: headerMask{mask: c.rxMask}}
}

type headerMask struct {
	mask           cipher.Stream
	header         [5]byte
	position, skip int
}

func (s *headerMask) transform(b []byte, decrypt bool) {
	for len(b) > 0 {
		if s.skip > 0 {
			n := min(len(b), s.skip)
			s.skip -= n
			b = b[n:]
			continue
		}
		n := min(len(b), 5-s.position)
		if !decrypt {
			copy(s.header[s.position:], b[:n])
		}
		s.mask.XORKeyStream(b[:n], b[:n])
		if decrypt {
			copy(s.header[s.position:], b[:n])
		}
		s.position += n
		b = b[n:]
		if s.position == 5 {
			s.skip = int(binary.BigEndian.Uint16(s.header[3:]))
			s.position = 0
		}
	}
}

type directConn struct {
	net.Conn
	owner  *Conn
	tx, rx headerMask
}

func (c *directConn) Write(b []byte) (int, error) {
	c.owner.writeMu.Lock()
	defer c.owner.writeMu.Unlock()
	if c.owner.writeErr != nil {
		return 0, c.owner.writeErr
	}
	out := append([]byte(nil), b...)
	c.tx.transform(out, false)
	if e := writeAll(c.Conn, out); e != nil {
		c.owner.writeErr = e
		return 0, e
	}
	return len(b), nil
}

func (c *directConn) Read(b []byte) (int, error) {
	c.owner.readMu.Lock()
	defer c.owner.readMu.Unlock()
	n, e := c.Conn.Read(b)
	if c.rx.mask == nil {
		c.rx.mask = c.owner.rxMask
	}
	c.rx.transform(b[:n], true)
	return n, e
}
func (c *directConn) CloseWrite() error { return c.owner.CloseWrite() }
func (c *directConn) CloseRead() error  { return c.owner.CloseRead() }
