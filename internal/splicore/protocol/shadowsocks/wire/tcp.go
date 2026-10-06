package wire

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

// Conn serializes each direction independently. Close only closes the socket;
// it never recycles/clears buffers that an in-flight Read or Write owns.
type Conn struct {
	net.Conn
	key            *Key
	client         bool
	requestSalt    []byte
	replay         *SaltCache
	rmu, wmu       sync.Mutex
	reader, writer cipher.AEAD
	rnonce, wnonce [12]byte
	pending        []byte
	rerr, werr     error
}

func (c *Conn) maxFrame() int {
	if c.key.Method.Edition == "2022" {
		return 65535
	}
	return 16383
}
func (c *Conn) open(b []byte) ([]byte, error) {
	p, e := c.reader.Open(nil, c.rnonce[:], b, nil)
	if e != nil {
		return nil, ErrAuth
	}
	if e = increment(c.rnonce[:]); e != nil {
		return nil, e
	}
	return p, nil
}
func (c *Conn) seal(b []byte) ([]byte, error) {
	p := c.writer.Seal(nil, c.wnonce[:], b, nil)
	if e := increment(c.wnonce[:]); e != nil {
		return nil, e
	}
	return p, nil
}
func (c *Conn) readChunk(length int) ([]byte, error) {
	if length < 0 || length > c.maxFrame() {
		return nil, ErrFrame
	}
	b := make([]byte, length+16)
	if _, e := io.ReadFull(c.Conn, b); e != nil {
		return nil, e
	}
	return c.open(b)
}
func (c *Conn) readFrame() ([]byte, error) {
	b := make([]byte, 18)
	if _, e := io.ReadFull(c.Conn, b); e != nil {
		return nil, e
	}
	p, e := c.open(b)
	if e != nil {
		return nil, e
	}
	return c.readChunk(int(binary.BigEndian.Uint16(p)))
}
func (c *Conn) frames(b []byte) ([]byte, error) {
	out := make([]byte, 0, len(b)+((len(b)/c.maxFrame())+1)*34)
	for len(b) > 0 {
		n := min(len(b), c.maxFrame())
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(n))
		l, e := c.seal(length[:])
		if e != nil {
			return nil, e
		}
		p, e := c.seal(b[:n])
		if e != nil {
			return nil, e
		}
		out = append(out, l...)
		out = append(out, p...)
		b = b[n:]
	}
	return out, nil
}
func ClientTCP(raw net.Conn, keys []*Key, dst access.Endpoint, replay *SaltCache) (*Conn, error) {
	if len(keys) == 0 {
		return nil, ErrAuth
	}
	key := keys[len(keys)-1]
	salt, e := random(key.Method.KeySize)
	if e != nil {
		return nil, e
	}
	c := &Conn{Conn: raw, key: key, client: true, requestSalt: salt, replay: replay}
	if key.Method.Edition == "2017" {
		if e = replay.Check(key, salt, time.Now()); e != nil {
			return nil, e
		}
	}
	c.writer, e = key.aead(salt)
	if e != nil {
		return nil, e
	}
	a, e := Address(dst)
	if e != nil {
		return nil, e
	}
	header := append([]byte(nil), salt...)
	if key.Method.Edition == "2017" {
		p, e := c.frames(a)
		if e != nil {
			return nil, e
		}
		header = append(header, p...)
	} else {
		for n := 0; n < len(keys)-1; n++ {
			block, e := keys[n].identity(salt)
			if e != nil {
				return nil, e
			}
			identity := make([]byte, 16)
			block.Encrypt(identity, keys[n+1].Hash[:])
			header = append(header, identity...)
		}
		padding, e := randomPadding()
		if e != nil {
			return nil, e
		}
		var variable bytes.Buffer
		variable.Write(a)
		binary.Write(&variable, binary.BigEndian, uint16(len(padding)))
		variable.Write(padding)
		fixed := make([]byte, 11)
		putTime(fixed[1:9], time.Now())
		binary.BigEndian.PutUint16(fixed[9:], uint16(variable.Len()))
		f, e := c.seal(fixed)
		if e != nil {
			return nil, e
		}
		v, e := c.seal(variable.Bytes())
		if e != nil {
			return nil, e
		}
		header = append(header, f...)
		header = append(header, v...)
	}
	if e = writeAll(raw, header); e != nil {
		return nil, e
	}
	return c, nil
}

// AcceptTCP authenticates against a fixed immutable list. Classic password trials
// never consume stream payload until a length chunk authenticates successfully.
func AcceptTCP(raw net.Conn, users []*Key, identity *Key, replay *SaltCache, now time.Time) (*Conn, access.Endpoint, int, error) {
	if len(users) == 0 {
		return nil, access.Endpoint{}, 0, ErrAuth
	}
	m := users[0].Method
	n := m.KeySize + 18
	if m.Edition == "2022" {
		n = m.KeySize + 27
		if identity != nil {
			n += 16
		}
	}
	header := make([]byte, n)
	if m.Edition == "2022" {
		read, e := raw.Read(header)
		if e != nil {
			return nil, access.Endpoint{}, 0, e
		}
		if read != len(header) {
			return nil, access.Endpoint{}, 0, ErrFrame
		}
	} else if _, e := io.ReadFull(raw, header); e != nil {
		return nil, access.Endpoint{}, 0, e
	}
	salt := header[:m.KeySize]
	chunk := header[m.KeySize:]
	selected := -1
	if identity != nil {
		block, e := identity.identity(salt)
		if e != nil {
			return nil, access.Endpoint{}, 0, e
		}
		var hash [16]byte
		block.Decrypt(hash[:], chunk[:16])
		chunk = chunk[16:]
		for n, k := range users {
			if subtle.ConstantTimeCompare(hash[:], k.Hash[:]) == 1 {
				selected = n
				break
			}
		}
		if selected < 0 {
			return nil, access.Endpoint{}, 0, ErrAuth
		}
	}
	var c *Conn
	var fixed []byte
	for n, k := range users {
		if selected >= 0 && selected != n {
			continue
		}
		aead, e := k.aead(salt)
		if e != nil {
			return nil, access.Endpoint{}, 0, e
		}
		trial := &Conn{Conn: raw, key: k, requestSalt: bytes.Clone(salt), reader: aead, replay: replay}
		p, e := trial.open(chunk)
		if e != nil {
			continue
		}
		c = trial
		fixed = p
		selected = n
		break
	}
	if c == nil {
		return nil, access.Endpoint{}, 0, ErrAuth
	}
	length := 0
	if m.Edition == "2022" {
		if len(fixed) != 11 || fixed[0] != 0 {
			return nil, access.Endpoint{}, 0, ErrFrame
		}
		if !timestampOK(binary.BigEndian.Uint64(fixed[1:9]), now) {
			return nil, access.Endpoint{}, 0, ErrTimestamp
		}
		length = int(binary.BigEndian.Uint16(fixed[9:]))
	} else {
		length = int(binary.BigEndian.Uint16(fixed))
	}
	p, e := c.readChunk(length)
	if e != nil {
		return nil, access.Endpoint{}, 0, e
	}
	if m.Edition == "2022" {
		r := bytes.NewReader(p)
		dst, e := ReadAddress(r)
		if e != nil {
			return nil, dst, 0, e
		}
		var pad uint16
		if binary.Read(r, binary.BigEndian, &pad) != nil || int(pad) > r.Len() || pad > MaxPadding || pad == 0 && r.Len() == 0 {
			return nil, dst, 0, ErrFrame
		}
		if _, e = r.Seek(int64(pad), io.SeekCurrent); e != nil {
			return nil, dst, 0, ErrFrame
		}
		c.pending = bytes.Clone(p[len(p)-r.Len():])
		if e = replay.Check(c.key, salt, now); e != nil {
			return nil, dst, 0, e
		}
		return c, dst, selected, nil
	}
	c.pending = p
	// The shared codec may read an address across classic AEAD frame boundaries.
	dst, e := ReadAddress(c)
	if e != nil {
		return nil, dst, 0, e
	}
	if e = replay.Check(c.key, salt, now); e != nil {
		return nil, dst, 0, e
	}
	return c, dst, selected, nil
}
func (c *Conn) readResponse() error {
	n := c.key.Method.KeySize
	if c.key.Method.Edition == "2022" {
		n += 27 + c.key.Method.KeySize
	}
	header := make([]byte, n)
	if c.key.Method.Edition == "2022" {
		read, e := c.Conn.Read(header)
		if e != nil {
			return e
		}
		if read != n {
			return ErrFrame
		}
	} else if _, e := io.ReadFull(c.Conn, header); e != nil {
		return e
	}
	salt := header[:c.key.Method.KeySize]
	aead, e := c.key.aead(salt)
	if e != nil {
		return e
	}
	c.reader = aead
	if c.key.Method.Edition == "2017" {
		return c.replay.Check(c.key, salt, time.Now())
	}
	f, e := c.open(header[c.key.Method.KeySize:])
	if e != nil {
		return e
	}
	if f[0] != 1 || !timestampOK(binary.BigEndian.Uint64(f[1:9]), time.Now()) {
		return ErrTimestamp
	}
	if subtle.ConstantTimeCompare(f[9:9+c.key.Method.KeySize], c.requestSalt) != 1 {
		return ErrAuth
	}
	p, e := c.readChunk(int(binary.BigEndian.Uint16(f[len(f)-2:])))
	if e != nil {
		return e
	}
	c.pending = p
	return nil
}
func (c *Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.rerr != nil {
		return 0, c.rerr
	}
	if c.reader == nil {
		if e := c.readResponse(); e != nil {
			c.rerr = e
			return 0, e
		}
	}
	// Zero-length authenticated classic chunks are skipped with a finite bound.
	for empty := 0; len(c.pending) == 0; empty++ {
		if empty >= 16 {
			c.rerr = ErrFrame
			return 0, c.rerr
		}
		p, e := c.readFrame()
		if e != nil {
			c.rerr = e
			return 0, e
		}
		c.pending = p
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *Conn) writeResponse(b []byte) (int, error) {
	salt, e := random(c.key.Method.KeySize)
	if e != nil {
		return 0, e
	}
	if c.key.Method.Edition == "2017" {
		if e = c.replay.Check(c.key, salt, time.Now()); e != nil {
			return 0, e
		}
	}
	c.writer, e = c.key.aead(salt)
	if e != nil {
		return 0, e
	}
	header := append([]byte(nil), salt...)
	consumed := 0
	if c.key.Method.Edition == "2022" {
		consumed = min(len(b), c.maxFrame())
		fixed := make([]byte, 11+c.key.Method.KeySize)
		fixed[0] = 1
		putTime(fixed[1:9], time.Now())
		copy(fixed[9:], c.requestSalt)
		binary.BigEndian.PutUint16(fixed[len(fixed)-2:], uint16(consumed))
		f, e := c.seal(fixed)
		if e != nil {
			return 0, e
		}
		p, e := c.seal(b[:consumed])
		if e != nil {
			return 0, e
		}
		header = append(header, f...)
		header = append(header, p...)
	}
	f, e := c.frames(b[consumed:])
	if e != nil {
		return 0, e
	}
	header = append(header, f...)
	if e = writeAll(c.Conn, header); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	// Bound temporary allocation even when a caller supplies a huge Write.
	total := 0
	for len(b) > 0 {
		n := min(len(b), c.maxFrame())
		var e error
		if c.writer == nil {
			_, e = c.writeResponse(b[:n])
		} else {
			var frame []byte
			frame, e = c.frames(b[:n])
			if e == nil {
				e = writeAll(c.Conn, frame)
			}
		}
		if e != nil {
			c.werr = e
			return total, e
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *Conn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Conn.Close()
}
