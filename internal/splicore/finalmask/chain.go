// Package finalmask composes reusable native TCP masks below transport security.
package finalmask

import (
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
)

// Wrap constructs from last to first: the first configured mask is innermost
// (closest to TLS/REALITY), and the last is closest to the socket.
func Wrap(raw net.Conn, c *cfg.Config, server bool) (net.Conn, error) {
	if c == nil {
		return raw, nil
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	var err error
	for i := len(c.TCP) - 1; i >= 0; i-- {
		v, e := cfg.Decode(c.TCP[i])
		if e != nil {
			return nil, e
		}
		b := newBase(raw)
		switch v := v.(type) {
		case cfg.Header:
			raw = &headerConn{base: b, config: v, server: server}
		case cfg.Fragment:
			// tlshello cannot recognize records after an inner encoding mask.
			// Treat those bytes as opaque rather than guessing from a random
			// first byte and corrupting a Sudoku stream with inserted headers.
			opaque := false
			for j := 0; j < i; j++ {
				if c.TCP[j].Type == "sudoku" {
					opaque = true
				}
			}
			raw = &fragmentConn{base: b, config: v, opaque: opaque}
		case cfg.Sudoku:
			raw, err = newSudoku(b, v, server)
		}
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

type base struct {
	net.Conn
	mu       sync.Mutex
	deadline time.Time
	changed  chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func newBase(c net.Conn) *base {
	return &base{Conn: c, changed: make(chan struct{}), closed: make(chan struct{})}
}
func (b *base) Close() error { b.once.Do(func() { close(b.closed) }); return b.Conn.Close() }
func (b *base) CloseWrite() error {
	if c, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return errors.New("half-close unsupported")
}
func (b *base) CloseRead() error {
	if c, ok := b.Conn.(interface{ CloseRead() error }); ok {
		return c.CloseRead()
	}
	return errors.New("half-close unsupported")
}
func (b *base) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
	return b.Conn.SetWriteDeadline(t)
}
func (b *base) SetDeadline(t time.Time) error {
	if e := b.SetWriteDeadline(t); e != nil {
		return e
	}
	return b.Conn.SetReadDeadline(t)
}
func (b *base) wait(d time.Duration) error {
	until := time.Now().Add(d)
	for {
		b.mu.Lock()
		dl, ch := b.deadline, b.changed
		b.mu.Unlock()
		now := time.Now()
		if !dl.IsZero() && !now.Before(dl) {
			return os.ErrDeadlineExceeded
		}
		if !now.Before(until) {
			return nil
		}
		end := until
		if !dl.IsZero() && dl.Before(end) {
			end = dl
		}
		timer := time.NewTimer(time.Until(end))
		select {
		case <-b.closed:
			timer.Stop()
			return net.ErrClosed
		case <-ch:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func pick(r cfg.Range) int {
	if r.Min == r.Max {
		return r.Min
	}
	return r.Min + rand.IntN(r.Max-r.Min+1)
}
func writeFull(w io.Writer, p []byte) error {
	_, e := writeFullCount(w, p)
	return e
}
func writeFullCount(w io.Writer, p []byte) (int, error) {
	sent := 0
	for len(p) > 0 {
		n, e := w.Write(p)
		if n < 0 || n > len(p) {
			return sent, io.ErrShortWrite
		}
		sent += n
		p = p[n:]
		if e != nil {
			return sent, e
		}
		if n == 0 {
			return sent, io.ErrNoProgress
		}
	}
	return sent, nil
}

// tlsProgress excludes inserted record headers from accepted input bytes.
func tlsProgress(records []byte, written int) int {
	accepted := min(5, written)
	for written > 5 && len(records) >= 5 {
		n := int(records[3])<<8 | int(records[4])
		accepted += min(n, written-5)
		if written < n+5 {
			break
		}
		written -= n + 5
		records = records[n+5:]
	}
	return accepted
}

type fragmentConn struct {
	*base
	config cfg.Fragment
	wmu    sync.Mutex
	count  uint64
	failed error
	opaque bool
}

func at(rs []cfg.Range, i int) cfg.Range {
	if i >= len(rs) {
		i = len(rs) - 1
	}
	return rs[i]
}
func (c *fragmentConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.failed != nil {
		return 0, c.failed
	}
	if len(p) == 0 {
		return 0, nil
	}
	c.count++
	tlshello := c.config.Packets == "tlshello"
	selected := true
	if tlshello {
		selected = !c.opaque && c.count == 1 && len(p) > 5 && p[0] == 22 && p[1] == 3 && p[2] <= 4 && p[5] == 1 && len(p) >= 5+(int(p[3])<<8|int(p[4]))
	} else if c.config.Packets != "" {
		r, _ := cfg.ParseRange(c.config.Packets, 1<<30)
		selected = c.count >= uint64(r.Min) && c.count <= uint64(r.Max)
	}
	if !selected {
		return c.Conn.Write(p)
	}
	limit := pick(c.config.MaxSplit)
	if limit == 0 {
		limit = 4096
	}
	data := p
	recordLen := 0
	if tlshello {
		recordLen = 5 + (int(p[3])<<8 | int(p[4]))
		data = p[5:recordLen]
	}
	merged := tlshello && len(c.config.Delays) == 1 && c.config.Delays[0].Max == 0
	var packed []byte
	sent := 0
	for i, from := 0, 0; from < len(data); i++ {
		n := pick(at(c.config.Lengths, i))
		if n > len(data)-from || i+1 >= limit {
			n = len(data) - from
		}
		part := data[from : from+n]
		if tlshello {
			part = append(append([]byte{}, p[:3]...), byte(n>>8), byte(n))
			part = append(part, data[from:from+n]...)
		}
		if merged {
			packed = append(packed, part...)
		} else {
			written, e := writeFullCount(c.Conn, part)
			if tlshello {
				if i == 0 {
					sent = min(5, written)
				}
				sent += max(0, written-5)
			} else {
				sent += written
			}
			if e != nil {
				c.failed = e
				return sent, e
			}
			if e := c.wait(time.Duration(pick(at(c.config.Delays, i))) * time.Millisecond); e != nil {
				c.failed = e
				return sent, e
			}
		}
		from += n
	}
	if merged {
		written, e := writeFullCount(c.Conn, packed)
		if e != nil {
			c.failed = e
			return tlsProgress(packed, written), e
		}
	}
	if tlshello && recordLen < len(p) {
		written, e := writeFullCount(c.Conn, p[recordLen:])
		if e != nil {
			c.failed = e
			return recordLen + written, e
		}
	}
	return len(p), nil
}
