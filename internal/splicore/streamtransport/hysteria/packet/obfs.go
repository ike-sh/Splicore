// Package packet owns Hysteria UDP transforms below QUIC. It contains no proxy
// authentication, stream, TLS or application session implementation.
package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/crypto/blake2b"
)

const (
	saltBytes     = 8
	frameBytes    = 5
	maxPacket     = 4096
	reassemblyTTL = 2 * time.Second
	maxMessages   = 512
	maxPerSource  = 256
	maxBuffered   = 2 << 20
)

var ErrPacket = errors.New("invalid or oversized Hysteria UDP packet")
var ErrEntropy = errors.New("Hysteria UDP entropy unavailable")
var ErrCapacity = errors.New("Hysteria UDP fragment capacity exhausted")

// No UDPConn, syscall.Conn, OOB, GSO or batching interfaces are advertised.
// Each transformed datagram is submitted separately; optimizations cannot skip
// framing or share caller-owned buffers. Underlying deadlines are preserved.
type Obfs struct {
	net.PacketConn
	config   cfg.HysteriaObfs
	mu       sync.Mutex
	closed   bool
	state    map[fragmentKey]*message
	sources  map[string]int
	buffered int
	sendIDs  [256]time.Time
	nextID   byte
	done     chan struct{}
	exited   chan struct{}
	once     sync.Once
	closeErr error
}
type fragmentKey struct {
	source string
	id     byte
}
type message struct {
	expires  time.Time
	total    byte
	chunks   [8][]byte
	mask     byte
	bytes    int
	terminal bool
}

// Wrap consumes packet only on success. The caller owns initialization failure.
func Wrap(p net.PacketConn, o *cfg.HysteriaObfs) (net.PacketConn, error) {
	if p == nil {
		return nil, ErrPacket
	}
	if o == nil {
		return p, nil
	}
	if o.Validate() != nil {
		return nil, ErrPacket
	}
	if o.Type == "none" {
		return p, nil
	}
	c := &Obfs{PacketConn: p, config: *o, state: make(map[fragmentKey]*message), sources: make(map[string]int), done: make(chan struct{}), exited: make(chan struct{})}
	if o.Type == "gecko" {
		var seed [1]byte
		if _, e := rand.Read(seed[:]); e != nil {
			return nil, ErrEntropy
		}
		c.nextID = seed[0]
		go c.sweep()
	} else {
		close(c.exited)
	}
	return c, nil
}
func (c *Obfs) sweep() {
	defer close(c.exited)
	timer := time.NewTicker(reassemblyTTL / 2)
	defer timer.Stop()
	for {
		select {
		case now := <-timer.C:
			c.mu.Lock()
			c.expire(now)
			c.mu.Unlock()
		case <-c.done:
			return
		}
	}
}
func (c *Obfs) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		clear(c.state)
		clear(c.sources)
		c.buffered = 0
		c.mu.Unlock()
		close(c.done)
		c.closeErr = c.PacketConn.Close()
		<-c.exited
	})
	return c.closeErr
}
func (c *Obfs) isClosed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }
func randomInt(lo, hi int) (int, error) {
	if lo > hi {
		return 0, ErrPacket
	}
	n, e := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	if e != nil {
		return 0, ErrEntropy
	}
	return lo + int(n.Int64()), nil
}

// saltMask creates an independent hash per datagram; no shared hash state.
func saltMask(password string, salt []byte) [32]byte {
	h, _ := blake2b.New256(nil)
	_, _ = h.Write([]byte(password))
	_, _ = h.Write(salt)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
func encode(password string, payload []byte) ([]byte, error) {
	out := make([]byte, saltBytes+len(payload))
	if _, e := rand.Read(out[:saltBytes]); e != nil {
		return nil, ErrEntropy
	}
	mask := saltMask(password, out[:saltBytes])
	for i, b := range payload {
		out[saltBytes+i] = b ^ mask[i%32]
	}
	return out, nil
}
func decode(password string, data []byte) bool {
	if len(data) <= saltBytes {
		return false
	}
	mask := saltMask(password, data[:saltBytes])
	for i := saltBytes; i < len(data); i++ {
		data[i-saltBytes] = data[i] ^ mask[(i-saltBytes)%32]
	}
	return true
}
func (c *Obfs) send(payload []byte, to net.Addr) error {
	if c.isClosed() {
		return net.ErrClosed
	}
	wire, e := encode(c.config.Password, payload)
	if e != nil {
		return e
	}
	n, e := c.PacketConn.WriteTo(wire, to)
	if e == nil && n != len(wire) {
		e = io.ErrShortWrite
	}
	return e
}
func (c *Obfs) nextMessage(now time.Time) (byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	for range 256 {
		id := c.nextID
		c.nextID++
		if !now.Before(c.sendIDs[id]) {
			c.sendIDs[id] = now.Add(reassemblyTTL)
			return id, nil
		}
	}
	return 0, ErrCapacity
}
func (c *Obfs) WriteTo(p []byte, to net.Addr) (int, error) {
	if len(p) == 0 || len(p) > maxPacket {
		return 0, ErrPacket
	}
	if c.config.Type != "gecko" || p[0]&0x80 == 0 {
		if e := c.send(p, to); e != nil {
			return 0, e
		}
		return len(p), nil
	}
	lo, hi := c.config.Sizes()
	capacity := hi - frameBytes - saltBytes
	minimum := max(2, (len(p)+capacity-1)/capacity)
	maximum := min(8, len(p))
	if minimum > maximum {
		return 0, ErrPacket
	}
	count, e := randomInt(minimum, maximum)
	if e != nil {
		return 0, e
	}
	id, e := c.nextMessage(time.Now())
	if e != nil {
		return 0, e
	}
	offset := 0
	for i := range count {
		remain := len(p) - offset
		slots := count - i - 1
		size, e := randomInt(max(1, remain-slots*capacity), min(capacity, remain-slots))
		if e != nil {
			return 0, e
		}
		wireSize, e := randomInt(max(lo, size+frameBytes+saltBytes), hi)
		if e != nil {
			return 0, e
		}
		pad := wireSize - saltBytes - frameBytes - size
		frame := make([]byte, frameBytes+pad+size)
		frame[0], frame[1], frame[2] = 0x80, id, byte(i<<4|count)
		binary.BigEndian.PutUint16(frame[3:5], uint16(pad))
		if _, e = rand.Read(frame[5 : 5+pad]); e != nil {
			return 0, ErrEntropy
		}
		copy(frame[5+pad:], p[offset:offset+size])
		if e = c.send(frame, to); e != nil {
			return 0, e
		}
		offset += size
	}
	return len(p), nil
}
func (c *Obfs) ReadFrom(p []byte) (int, net.Addr, error) {
	var raw [65535]byte
	for {
		n, from, e := c.PacketConn.ReadFrom(raw[:])
		if e != nil {
			return 0, nil, e
		}
		if c.isClosed() {
			return 0, nil, net.ErrClosed
		}
		if from == nil || len(from.String()) > 512 || !decode(c.config.Password, raw[:n]) {
			continue
		}
		payload := raw[:n-saltBytes]
		if c.config.Type == "gecko" && payload[0]&0x80 != 0 {
			payload = c.fragment(payload, from, time.Now())
			if payload == nil {
				continue
			}
		}
		if len(payload) > maxPacket {
			continue
		}
		if len(payload) > len(p) {
			return 0, from, io.ErrShortBuffer
		}
		return copy(p, payload), from, nil
	}
}
func (c *Obfs) expire(now time.Time) {
	for key, m := range c.state {
		if !now.Before(m.expires) {
			delete(c.state, key)
			c.sources[key.source]--
			if c.sources[key.source] == 0 {
				delete(c.sources, key.source)
			}
			c.buffered -= m.bytes
		}
	}
}
func (c *Obfs) retire(m *message) {
	c.buffered -= m.bytes
	m.bytes = 0
	m.chunks = [8][]byte{}
	m.terminal = true
}
func (c *Obfs) fragment(frame []byte, from net.Addr, now time.Time) []byte {
	if len(frame) < frameBytes+1 || len(frame)+saltBytes > 2048 || frame[0] != 0x80 {
		return nil
	}
	id, index, total := frame[1], frame[2]>>4, frame[2]&15
	pad := int(binary.BigEndian.Uint16(frame[3:5]))
	if total < 2 || total > 8 || index >= total || pad > len(frame)-frameBytes-1 {
		return nil
	}
	chunk := frame[frameBytes+pad:]
	if len(chunk) > maxPacket {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.expire(now)
	key := fragmentKey{from.Network() + "/" + from.String(), id}
	m := c.state[key]
	if m == nil {
		if len(c.state) >= maxMessages || c.sources[key.source] >= maxPerSource {
			return nil
		}
		m = &message{expires: now.Add(reassemblyTTL), total: total}
		c.state[key] = m
		c.sources[key.source]++
	}
	if m.terminal {
		return nil
	}
	if m.total != total {
		c.retire(m)
		return nil
	}
	if m.mask&(1<<index) != 0 {
		if !bytes.Equal(m.chunks[index], chunk) {
			c.retire(m)
		}
		return nil
	}
	if m.bytes+len(chunk) > maxPacket || c.buffered+len(chunk) > maxBuffered {
		c.retire(m)
		return nil
	}
	m.chunks[index] = bytes.Clone(chunk)
	m.mask |= 1 << index
	m.bytes += len(chunk)
	c.buffered += len(chunk)
	if m.mask != byte((1<<total)-1) {
		return nil
	}
	out := make([]byte, 0, m.bytes)
	for i := byte(0); i < total; i++ {
		out = append(out, m.chunks[i]...)
	}
	c.retire(m)
	if len(out) == 0 || out[0]&0x80 == 0 {
		return nil
	}
	return out
}
