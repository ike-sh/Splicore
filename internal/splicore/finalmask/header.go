package finalmask

import (
	"bytes"
	"errors"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"io"
	"sync"
	"time"
)

type headerConn struct {
	*base
	config   cfg.Header
	server   bool
	once     sync.Once
	err      error
	rmu, wmu sync.Mutex
}

func (c *headerConn) send(seq []cfg.Item) error {
	var packet []byte
	flush := func() error {
		if len(packet) == 0 {
			return nil
		}
		e := writeFull(c.Conn, packet)
		packet = nil
		return e
	}
	for _, item := range seq {
		if item.Delay.Max > 0 {
			if e := flush(); e != nil {
				return e
			}
			if e := c.wait(time.Duration(pick(item.Delay)) * time.Millisecond); e != nil {
				return e
			}
		}
		b, _ := item.Bytes()
		if item.Rand > 0 {
			r := cfg.Range{Min: 0, Max: 255}
			if item.RandRange != nil {
				r = *item.RandRange
			}
			b = make([]byte, item.Rand)
			for i := range b {
				b[i] = byte(pick(r))
			}
		}
		packet = append(packet, b...)
	}
	return flush()
}
func (c *headerConn) receive(seq []cfg.Item) error {
	for _, item := range seq {
		want, _ := item.Bytes()
		n := len(want)
		if item.Rand > 0 {
			n = item.Rand
		}
		b := make([]byte, n)
		if _, e := io.ReadFull(c.Conn, b); e != nil {
			return e
		}
		if item.Rand == 0 && !bytes.Equal(b, want) {
			return errors.New("FinalMask header mismatch")
		}
	}
	return nil
}
func (c *headerConn) handshake() {
	c.once.Do(func() {
		for i, seq := range c.config.Clients {
			if c.server {
				c.err = c.receive(seq)
				if c.err != nil {
					if i < len(c.config.Errors) {
						_ = c.send(c.config.Errors[i])
					}
					return
				}
				if i < len(c.config.Servers) {
					c.err = c.send(c.config.Servers[i])
				}
			} else {
				c.err = c.send(seq)
				if c.err == nil && i < len(c.config.Servers) {
					c.err = c.receive(c.config.Servers[i])
				}
			}
			if c.err != nil {
				return
			}
		}
		for i := len(c.config.Clients); i < len(c.config.Servers); i++ {
			if c.server {
				c.err = c.send(c.config.Servers[i])
			} else {
				c.err = c.receive(c.config.Servers[i])
			}
			if c.err != nil {
				return
			}
		}
	})
}
func (c *headerConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	c.handshake()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}
func (c *headerConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.handshake()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(p)
}
