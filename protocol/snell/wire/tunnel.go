package wire

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
)

type transport struct {
	raw   net.Conn
	read  *Decoder
	write *Encoder
}

func newTransport(c net.Conn, k *Key) *transport {
	return &transport{c, NewDecoder(c, k), NewEncoder(c, k)}
}

// Tunnel owns one logical request. Its read cache belongs to rmu and is never
// cleared by Close. The server transfers the transport to a new Tunnel only
// after the callback has joined all payload workers.
type Tunnel struct {
	net.Conn
	t                         *transport
	server, reusable          bool
	request                   Request
	rmu, wmu                  sync.Mutex
	cache                     []byte
	readStarted, writeStarted bool
	readEnd, writeEnd         atomic.Bool
}

func ClientTCP(c net.Conn, k *Key, dst access.Endpoint) (net.Conn, error) {
	q := Request{Command: 5, Destination: dst}
	if _, e := EncodeRequest(q); e != nil {
		return nil, e
	}
	return &Tunnel{Conn: c, t: newTransport(c, k), request: q}, nil
}
func (c *Tunnel) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeEnd.Load() {
		return 0, net.ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.writeStarted {
		return c.t.write.Write(p)
	}
	var prefix []byte
	if c.server {
		prefix = []byte{0}
	} else {
		var e error
		prefix, e = EncodeRequest(c.request)
		if e != nil {
			return 0, e
		}
	}
	first := make([]byte, 0, len(prefix)+len(p))
	first = append(first, prefix...)
	first = append(first, p...)
	// v6's initial command/reply submission is capped at the u16 payload
	// boundary before shaped chunking; its remainder is a separate submission.
	// This affects chunk boundaries even when individual chunks are smaller.
	boundary := len(first)
	if c.t.write.key.version == 6 {
		boundary = min(boundary, 65535)
	}
	if _, e := c.t.write.Write(first[:boundary]); e != nil {
		return 0, e
	}
	if boundary < len(first) {
		if _, e := c.t.write.Write(first[boundary:]); e != nil {
			return 0, e
		}
	}
	c.writeStarted = true
	return len(p), nil
}
func (c *Tunnel) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readEnd.Load() {
		return 0, io.EOF
	}
	if !c.server && !c.readStarted {
		c.wmu.Lock()
		if !c.writeStarted {
			q, e := EncodeRequest(c.request)
			if e == nil {
				_, e = c.t.write.Write(q)
			}
			if e != nil {
				c.wmu.Unlock()
				return 0, e
			}
			c.writeStarted = true
		}
		c.wmu.Unlock()
		p, e := c.t.read.Next()
		if e != nil {
			return 0, e
		}
		c.cache, e = tunnelReply(p)
		if e != nil {
			return 0, e
		}
		c.readStarted = true
	}
	for len(c.cache) == 0 {
		var e error
		c.cache, e = c.t.read.Next()
		if e != nil {
			if errors.Is(e, io.EOF) {
				c.readEnd.Store(true)
			}
			return 0, e
		}
	}
	n := copy(p, c.cache)
	c.cache = c.cache[n:]
	return n, nil
}
func (c *Tunnel) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeEnd.Load() {
		return nil
	}
	if c.server && !c.reusable {
		c.writeEnd.Store(true)
		return c.Conn.Close()
	}
	if !c.writeStarted {
		if c.server {
			// A target that closes before producing data aborts a reusable request.
			_, e := c.t.write.Write(append([]byte{2, 0x65, 10}, "Remote EOF"...))
			_ = c.Conn.Close()
			return e
		}
		q, e := EncodeRequest(c.request)
		if e != nil {
			return e
		}
		if _, e = c.t.write.Write(q); e != nil {
			return e
		}
		c.writeStarted = true
	}
	if e := c.t.write.Record(nil); e != nil {
		return e
	}
	c.writeEnd.Store(true)
	return nil
}
func (c *Tunnel) Close() error {
	// A clean completed server request relinquishes its borrow. Any incomplete
	// Close aborts the raw transport, unblocking reads without touching cache.
	if c.server && c.reusable && c.readEnd.Load() && c.writeEnd.Load() {
		return nil
	}
	return c.Conn.Close()
}

// Serve's callbacks run synchronously and must join their workers before return.
// All accepted raw sockets remain owned by the enclosing runtime throughout.
func Serve(c net.Conn, k *Key, tcp func(*Tunnel, access.Endpoint) error, udp func(*Packet) error) error {
	t := newTransport(c, k)
	for {
		p, e := t.read.Next()
		if e != nil {
			return e
		}
		q, rest, e := DecodeRequest(p, k.version)
		if e != nil {
			return e
		}
		switch q.Command {
		case 0:
			_, e = t.write.Write([]byte{1})
			return e
		case 6:
			if k.version == 6 && len(rest) != 0 {
				return ErrFrame
			}
			if e = t.write.Record([]byte{0}); e != nil {
				return e
			}
			return udp(&Packet{raw: c, t: t, server: true})
		case 1, 5:
			logical := &Tunnel{Conn: c, t: t, server: true, reusable: q.Command == 5, cache: rest, request: q}
			if e = tcp(logical, q.Destination); e != nil {
				return e
			}
			if e = logical.CloseWrite(); e != nil {
				return e
			}
			if !logical.reusable {
				return nil
			}
			if !logical.readEnd.Load() {
				discarded := 0
				for {
					data, e := t.read.Next()
					if errors.Is(e, io.EOF) {
						break
					}
					if e != nil {
						return e
					}
					discarded += len(data)
					if discarded >= 2*1024*1024 {
						return ErrFrame
					}
				}
			}
		}
	}
}

type Packet struct {
	raw       net.Conn
	t         *transport
	server    bool
	target    access.Endpoint
	rmu       sync.Mutex
	replyOnce sync.Once
	replyErr  error
}

func ClientPacket(c net.Conn, k *Key, dst access.Endpoint) (net.PacketConn, error) {
	t := newTransport(c, k)
	q, e := EncodeRequest(Request{Command: 6})
	if e != nil {
		return nil, e
	}
	if e = t.write.Record(q); e != nil {
		return nil, e
	}
	p := &Packet{raw: c, t: t, target: dst}
	// Finish the server reply under the constructor's handshake deadline and
	// context ownership. A returned Packet must not perform a read in WriteTo,
	// where SetWriteDeadline cannot interrupt a pending handshake read.
	if e = p.reply(); e != nil {
		return nil, e
	}
	return p, nil
}
func (p *Packet) reply() error {
	if p.server {
		return nil
	}
	p.replyOnce.Do(func() {
		data, e := p.t.read.Next()
		if e != nil {
			p.replyErr = e
			return
		}
		remaining, e := tunnelReply(data)
		if e != nil {
			p.replyErr = e
			return
		}
		if len(remaining) != 0 {
			p.replyErr = ErrFrame
		}
	})
	return p.replyErr
}
func (p *Packet) WriteTo(b []byte, a net.Addr) (int, error) {
	e := p.reply()
	if e != nil {
		return 0, e
	}
	dst := p.target
	if a != nil {
		dst, e = netaddr.From(a)
		if e != nil {
			return 0, e
		}
	}
	frame, e := EncodeDatagram(dst, b, p.server)
	if e != nil {
		return 0, e
	}
	if e = p.t.write.Record(frame); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (p *Packet) ReadFrom(b []byte) (int, net.Addr, error) {
	p.rmu.Lock()
	defer p.rmu.Unlock()
	if e := p.reply(); e != nil {
		return 0, nil, e
	}
	frame, e := p.t.read.Next()
	if e != nil {
		return 0, nil, e
	}
	dst, payload, e := DecodeDatagram(frame, !p.server)
	if e != nil {
		return 0, nil, e
	}
	if len(payload) > len(b) {
		return 0, nil, io.ErrShortBuffer
	}
	return copy(b, payload), netaddr.UDP(dst), nil
}
func (p *Packet) Close() error                       { return p.raw.Close() }
func (p *Packet) LocalAddr() net.Addr                { return p.raw.LocalAddr() }
func (p *Packet) SetDeadline(t time.Time) error      { return p.raw.SetDeadline(t) }
func (p *Packet) SetReadDeadline(t time.Time) error  { return p.raw.SetReadDeadline(t) }
func (p *Packet) SetWriteDeadline(t time.Time) error { return p.raw.SetWriteDeadline(t) }
