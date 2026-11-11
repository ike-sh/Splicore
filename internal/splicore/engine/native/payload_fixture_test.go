package native

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

// Unchanged generic payload/half-close fixture retained for admitted Snell tests.
func sqExchange(c net.Conn, size int, half bool) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*17 + size)
	}
	result := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); {
			end := min(len(payload), off+211)
			if _, e := c.Write(payload[off:end]); e != nil {
				result <- e
				return
			}
			off = end
		}
		if half {
			w, ok := c.(interface{ CloseWrite() error })
			if !ok {
				result <- errors.New("missing half close")
				return
			}
			result <- w.CloseWrite()
			return
		}
		result <- nil
	}()
	b := make([]byte, size)
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if !bytes.Equal(payload, b) {
		return errors.New("byte mismatch")
	}
	if e := <-result; e != nil {
		return e
	}
	if half {
		var b [1]byte
		if _, e := c.Read(b[:]); e != io.EOF {
			return errors.New("missing EOF")
		}
	}
	return nil
}
