package native

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
)

func TestInheritedLookaheadTransferReadCloseOwnership(t *testing.T) {
	for range 128 {
		a, b := net.Pipe()
		buffer := bytes.Repeat([]byte{42}, 64)
		cached := traffic.Prefix(a, buffer)
		clear(buffer) // The owned reader retains only its immutable snapshot.
		counted := meteredConn(cached, &meter{})
		first := make([]byte, 8)
		if n, err := counted.Read(first); n != 8 || err != nil || !bytes.Equal(first, bytes.Repeat([]byte{42}, 8)) {
			t.Fatal("lookahead was lost", n, err)
		}
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Go(func() { <-start; _, _ = io.Copy(io.Discard, counted) })
		workers.Go(func() { <-start; _ = cached.Close() })
		workers.Go(func() { <-start; _ = counted.Close() })
		close(start)
		workers.Wait()
		_ = b.Close()
	}
}
