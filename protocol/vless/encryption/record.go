package encryption

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// Conn streams authenticated records, with separate direction locks and bounded
// buffering. Random appearance transforms only record headers, never payloads.
type Conn struct {
	random bool
	net.Conn
	readMu, writeMu   sync.Mutex
	rx, tx            *cryptor
	rxMask, txMask    cipher.Stream
	united            []byte
	aesMode           bool
	pending, prefix   []byte
	peerPadding       int
	resumed           bool
	client            *Client
	generation        uint64
	readErr, writeErr error
}

func headerSize(h []byte) (int, error) {
	if len(h) != 5 || h[0] != 23 || h[1] != 3 || h[2] != 3 {
		return 0, ErrRecord
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n < 17 || n > 16640 {
		return 0, ErrRecord
	}
	return n, nil
}
func header(n int) []byte { return []byte{23, 3, 3, byte(n >> 8), byte(n)} }
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return io.ErrShortWrite
		}
		p = p[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	done := 0
	for len(p) > 0 {
		n := min(len(p), 8192)
		h := header(n + 16)
		renew := c.tx.terminal()
		body := c.tx.seal(p[:n], h)
		if renew {
			c.tx = newCryptor(append(append([]byte(nil), h...), body...), c.united, c.aesMode)
		}
		if c.txMask != nil {
			c.txMask.XORKeyStream(h, h)
		}
		frame := make([]byte, 0, len(c.prefix)+5+len(body))
		frame = append(frame, c.prefix...)
		frame = append(frame, h...)
		frame = append(frame, body...)
		c.prefix = nil
		if e := writeAll(c.Conn, frame); e != nil {
			c.writeErr = e
			return done, e
		}
		done += n
		p = p[n:]
	}
	return done, nil
}

func (c *Conn) Read(p []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) > 0 {
		n = copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	defer func() {
		if err != nil {
			c.readErr = err
			if c.client != nil {
				c.client.invalidate(c.generation)
			}
		}
	}()
	if c.rx == nil {
		iv := make([]byte, 16)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}
		c.rx = newCryptor(iv, c.united, c.aesMode)
		if c.random {
			c.rxMask = stream(c.united, iv)
		}
	}
	if c.peerPadding > 0 {
		b := make([]byte, c.peerPadding)
		if _, err = io.ReadFull(c.Conn, b); err != nil {
			return
		}
		if _, err = c.rx.open(b, nil); err != nil {
			return 0, ErrHandshake
		}
		c.peerPadding = 0
	}
	h := make([]byte, 5)
	if _, err = io.ReadFull(c.Conn, h); err != nil {
		return
	}
	if c.rxMask != nil {
		c.rxMask.XORKeyStream(h, h)
	}
	size, e := headerSize(h)
	if e != nil {
		if c.client != nil {
			return 0, ErrResume
		}
		return 0, e
	}
	body := make([]byte, size)
	if _, err = io.ReadFull(c.Conn, body); err != nil {
		return
	}
	var renew *cryptor
	if c.rx.terminal() {
		renew = newCryptor(append(append([]byte(nil), h...), body...), c.united, c.aesMode)
	}
	plain, e := c.rx.open(body, h)
	if e != nil {
		return 0, ErrRecord
	}
	if renew != nil {
		c.rx = renew
	}
	c.client = nil
	n = copy(p, plain)
	c.pending = plain[n:]
	return n, nil
}

func (c *Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return io.ErrClosedPipe
}

func (c *Conn) CloseRead() error {
	if h, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return h.CloseRead()
	}
	return io.ErrClosedPipe
}
