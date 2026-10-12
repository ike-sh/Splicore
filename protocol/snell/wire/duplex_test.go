package wire

import (
	"bytes"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"io"
	"net"
	"testing"
	"time"
)

// An unbuffered transport forces the server to return data before a large
// initial client write completes. TCP socket buffers can hide this deadlock.
func TestInitialTCPWriteAllowsConcurrentReply(t *testing.T) {
	for _, version := range []int{4, 5, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(5 * time.Second))
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			key := keyFor(t, version)
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				done <- Serve(b, key, func(c *Tunnel, _ access.Endpoint) error { _, e := io.Copy(c, c); return e }, func(*Packet) error { return ErrFrame })
			}()
			c, e := ClientTCP(a, key, access.Endpoint{Host: "localhost", Port: 443})
			if e != nil {
				t.Fatal(e)
			}
			if _, e := c.Write(nil); e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte{0, 255, 33}, 100000)
			written := make(chan error, 1)
			go func() {
				_, e := c.Write(payload)
				if e == nil {
					e = c.(interface{ CloseWrite() error }).CloseWrite()
				}
				written <- e
			}()
			got, e := io.ReadAll(c)
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatal("initial duplex response", e)
			}
			if e := <-written; e != nil {
				t.Fatal(e)
			}
			_ = c.Close()
			<-done
		})
	}
}
