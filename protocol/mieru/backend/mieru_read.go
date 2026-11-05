package backend

import (
	"io"
	"net"
	"sync"
	"time"
)

// mieruReadConn keeps application read deadlines outside the SDK: Session.Read
// clears its deadline after every call and snapshots it before blocking. The
// SDK's lazy handshake also owns a separate read deadline. Neither may replace
// a caller's deadline, including during io.ReadFull or an in-flight Read.
//
// One reader and net.Pipe provide persistent, live deadlines without sharing
// caller buffers with an SDK operation that outlives a timed-out Read. At most
// io.Copy's 32 KiB buffer is prefetched; the pipe preserves backpressure. Close
// interrupts the SDK session and joins this reader. Writes retain SDK semantics.
// Requires mieru >= v3.39.0, which removes unsolicited client response timeouts.
type mieruReadConn struct {
	net.Conn
	reader  net.Conn
	writer  net.Conn
	done    chan struct{}
	once    sync.Once
	err     error
	readErr error // published by closing done, before a reader observes EOF
}

func newMieruReadConn(conn net.Conn) *mieruReadConn {
	r, w := net.Pipe()
	c := &mieruReadConn{Conn: conn, reader: r, writer: w, done: make(chan struct{})}
	go func() {
		// Hide optional WriterTo methods so the prefetch bound is explicit.
		_, c.readErr = io.CopyBuffer(w, struct{ io.Reader }{conn}, make([]byte, 32<<10))
		w.Close()
		close(c.done)
	}()
	return c
}

func (c *mieruReadConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := c.reader.Read(b)
	if err == io.EOF {
		<-c.done
		if c.readErr != nil {
			err = c.readErr
		}
	}
	return n, err
}

func (c *mieruReadConn) SetReadDeadline(t time.Time) error {
	return c.reader.SetReadDeadline(t)
}

func (c *mieruReadConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *mieruReadConn) Close() error {
	c.once.Do(func() {
		c.reader.Close()
		c.writer.Close()
		c.err = c.Conn.Close()
		<-c.done
	})
	return c.err
}
