package wire

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestPacketConstructorOwnsReplyDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(io.Discard, server) }()
	client.SetDeadline(time.Now().Add(time.Millisecond))
	p, err := ClientPacket(client, keyFor(t, 6), access.Endpoint{Host: "127.0.0.1", Port: 12345})
	if p != nil {
		t.Fatal("exposed packet before server reply completed")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	client.Close()
	<-done
}
