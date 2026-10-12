package wire

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// HTTP obfs wraps only the first submission in each direction. Content-Length
// describes that submission, not an HTTP framing rule for the tunnel.
type httpConn struct {
	net.Conn
	reader                    *bufio.Reader
	server                    bool
	host, uri                 string
	rmu, wmu                  sync.Mutex
	readStarted, writeStarted bool
	readErr, writeErr         error
}

// HTTPClient requires a validated host and origin-form URI from version policy.
func HTTPClient(c net.Conn, host, uri string) net.Conn {
	return &httpConn{Conn: c, reader: bufio.NewReader(c), host: host, uri: uri}
}
func HTTPServer(c net.Conn) net.Conn {
	return &httpConn{Conn: c, reader: bufio.NewReader(c), server: true}
}
func (c *httpConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if !c.readStarted {
		c.readStarted = true
		c.readErr = c.header()
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}
func (c *httpConn) header() error {
	// Bounded parsing retains coalesced payload without unbounded allocation.
	buf := make([]byte, 0, 1024)
	for len(buf) < 8192 {
		b, e := c.reader.ReadByte()
		if e != nil {
			return e
		}
		buf = append(buf, b)
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			lines := strings.Split(string(buf), "\r\n")
			if c.server {
				parts := strings.Split(lines[0], " ")
				if len(parts) != 3 || parts[0] != "GET" || !strings.HasPrefix(parts[1], "/") || parts[2] != "HTTP/1.1" {
					return ErrFrame
				}
			} else if !strings.HasPrefix(lines[0], "HTTP/1.1 101 ") && !strings.HasPrefix(lines[0], "HTTP/1.1 200 ") {
				return ErrFrame
			}
			for _, line := range lines[1 : len(lines)-2] {
				if !strings.Contains(line, ":") {
					return ErrFrame
				}
				for _, b := range []byte(line) {
					if b < 32 && b != '\t' || b == 127 {
						return ErrFrame
					}
				}
			}
			return nil
		}
	}
	return ErrFrame
}
func (c *httpConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !c.writeStarted {
		var header string
		if c.server {
			header = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		} else {
			var key [16]byte
			if _, e := io.ReadFull(rand.Reader, key[:]); e != nil {
				c.writeErr = e
				return 0, e
			}
			header = fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: %d\r\nSec-WebSocket-Key: %s\r\n\r\n", c.uri, c.host, len(p), base64.StdEncoding.EncodeToString(key[:]))
		}
		c.writeStarted = true
		c.writeErr = exactWrite(c.Conn, append([]byte(header), p...))
		if c.writeErr != nil {
			return 0, c.writeErr
		}
		return len(p), nil
	}
	n, e := c.Conn.Write(p)
	c.writeErr = e
	return n, e
}
