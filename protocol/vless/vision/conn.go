package vision

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
)

var ErrFrame = errors.New("invalid Vision frame")

const Flow = "xtls-rprx-vision"

type Conn struct {
	net.Conn                         // secured VLESS body, including lazy response framing
	raw                     net.Conn // masked underlay, never the unmasked socket
	plain                   *PlainConn
	uuid                    [16]byte
	rmu, wmu                sync.Mutex
	firstRead, firstWrite   bool
	rmode, wmode            byte
	pending                 []byte
	readErr, writeErr       error
	empty                   int
	state                   detection
	readDirect, writeDirect atomic.Bool
}

func New(body net.Conn, plain *PlainConn, raw net.Conn, uuid [16]byte) *Conn {
	return &Conn{Conn: body, plain: plain, raw: raw, uuid: uuid, firstRead: true, firstWrite: true}
}

// DirectState exposes negotiated direction state for diagnostics.
func (c *Conn) DirectState() (read, write bool) { return c.readDirect.Load(), c.writeDirect.Load() }
func (c *Conn) Close() error                    { return c.raw.Close() }
func (c *Conn) CloseRead() error                { return halfRead(c.raw) }
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wmode == 2 {
		return halfWrite(c.raw)
	}
	return halfWrite(c.Conn)
}
func (c *Conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 && c.readErr == nil {
		if c.rmode != 0 {
			r := c.Conn
			if c.rmode == 2 {
				r = c.raw
			}
			n, e := r.Read(p)
			return n, e
		}
		if c.firstRead {
			var id [16]byte
			if _, e := io.ReadFull(c.Conn, id[:]); e != nil {
				c.readErr = e
				break
			}
			if id != c.uuid {
				c.readErr = ErrFrame
				break
			}
			c.firstRead = false
		}
		var h [5]byte
		if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
			c.readErr = e
			break
		}
		size := int(binary.BigEndian.Uint16(h[1:3]))
		padding := int(binary.BigEndian.Uint16(h[3:]))
		if h[0] > 2 || size+padding > 65535 {
			c.readErr = ErrFrame
			break
		}
		b := make([]byte, size+padding)
		if _, e := io.ReadFull(c.Conn, b); e != nil {
			c.readErr = e
			break
		}
		c.pending = b[:size]
		c.state.inspect(false, c.pending)
		if size == 0 {
			c.empty++
			if c.empty > 4096 {
				c.readErr = ErrFrame
				break
			}
		} else {
			c.empty = 0
		}
		c.rmode = h[0]
		if c.rmode == 2 {
			c.pending = append(c.pending, c.plain.drain()...)
			c.readDirect.Store(true)
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return 0, c.readErr
}
func (c *Conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.wmode != 0 {
		w := c.Conn
		if c.wmode == 2 {
			w = c.raw
		}
		return w.Write(p)
	}
	c.state.inspect(true, p)
	tlsTraffic, eligible, stop := c.state.flags()
	command := byte(0)
	if tlsTraffic && completeApplications(p) {
		command = 1
		if eligible {
			command = 2
		}
	} else if stop && !tlsTraffic {
		command = 1
	}
	sent := 0
	for len(p) > 0 {
		n := min(len(p), 8192)
		cmd := byte(0)
		if n == len(p) {
			cmd = command
		}
		pad := rand.IntN(256)
		if tlsTraffic && n < 900 {
			pad = 900 - n + rand.IntN(500)
		}
		b := make([]byte, 0, 21+n+pad)
		if c.firstWrite {
			b = append(b, c.uuid[:]...)
			c.firstWrite = false
		}
		b = append(b, cmd, byte(n>>8), byte(n), byte(pad>>8), byte(pad))
		b = append(b, p[:n]...)
		b = append(b, make([]byte, pad)...)
		prefix := len(b) - n - pad
		count, e := c.Conn.Write(b)
		if count < 0 || count > len(b) {
			count = 0
			e = io.ErrShortWrite
		}
		if e == nil && count != len(b) {
			e = io.ErrShortWrite
		}
		if e != nil {
			c.writeErr = e
			return sent + min(n, max(0, count-prefix)), e
		}
		sent += n
		p = p[n:]
	}
	c.wmode = command
	if command == 2 {
		c.writeDirect.Store(true)
	}
	return sent, nil
}
func completeApplications(p []byte) bool {
	if len(p) < 5 {
		return false
	}
	for len(p) > 0 {
		if len(p) < 5 || !bytes.Equal(p[:3], []byte{23, 3, 3}) {
			return false
		}
		n := 5 + int(binary.BigEndian.Uint16(p[3:5]))
		if n > len(p) {
			return false
		}
		p = p[n:]
	}
	return true
}

// Both directions share TLS detection, while partial record storage is owned
// separately. ServerHello extensions are parsed, not searched as substrings.
type detection struct {
	mu                  sync.Mutex
	buffers             [2][]byte
	invalid             [2]bool
	count               int
	tls, eligible, done bool
}

func (d *detection) flags() (bool, bool, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tls, d.eligible, d.done || d.count >= 8
}
func (d *detection) inspect(write bool, p []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(p) == 0 || d.done {
		return
	}
	d.count++
	i := 0
	if write {
		i = 1
	}
	if d.invalid[i] {
		return
	}
	b := append(d.buffers[i], p...)
	if len(b) > 65540 {
		d.invalid[i] = true
		d.buffers[i] = nil
		return
	}
	for len(b) >= 5 {
		if b[0] < 20 || b[0] > 23 || b[1] != 3 {
			d.invalid[i] = true
			b = nil
			break
		}
		n := 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if n > 18437 {
			d.invalid[i] = true
			b = nil
			break
		}
		if len(b) < n {
			break
		}
		r := b[:n]
		b = b[n:]
		if r[0] != 22 || len(r) < 9 {
			continue
		}
		if r[5] == 1 {
			d.tls = true
		}
		if r[5] != 2 {
			continue
		}
		d.tls = true
		d.done = true
		hello := r[9:]
		if len(hello) < 35 {
			continue
		}
		sid := int(hello[34])
		off := 35 + sid
		if off+5 > len(hello) {
			continue
		}
		cipher := binary.BigEndian.Uint16(hello[off:])
		off += 3
		extLen := int(binary.BigEndian.Uint16(hello[off:]))
		off += 2
		if off+extLen > len(hello) {
			continue
		}
		ext := hello[off : off+extLen]
		for len(ext) >= 4 {
			typ := binary.BigEndian.Uint16(ext)
			size := int(binary.BigEndian.Uint16(ext[2:]))
			ext = ext[4:]
			if size > len(ext) {
				break
			}
			if typ == 43 && size == 2 && bytes.Equal(ext[:size], []byte{3, 4}) && cipher >= 0x1301 && cipher <= 0x1304 {
				d.eligible = true
			}
			ext = ext[size:]
		}
	}
	d.buffers[i] = b
}
