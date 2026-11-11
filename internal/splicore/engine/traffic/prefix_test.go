package traffic

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
)

func TestHandshakePrefixOwnsBytesThroughConcurrentClose(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	source := bytes.Repeat([]byte{42}, 65536)
	c := Prefix(a, source)
	clear(source)
	first := make([]byte, 8)
	if n, err := c.Read(first); err != nil || n != 8 || !bytes.Equal(first, bytes.Repeat([]byte{42}, 8)) {
		t.Fatal("lookahead did not own its snapshot", n, err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		buf := make([]byte, 1)
		for {
			n, err := c.Read(buf)
			if n > 0 && buf[0] != 42 {
				t.Error("prefix mutated during Close")
			}
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				return
			}
		}
	})
	for range 16 {
		workers.Go(func() { <-start; _ = c.Close() })
	}
	close(start)
	workers.Wait()
	if _, err := c.Read(first); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed prefix remained readable", err)
	}
}
