package wire

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

type writeObservation struct {
	net.Conn
	armed   atomic.Bool
	entered chan struct{}
}

func (c *writeObservation) Write(b []byte) (int, error) {
	if c.armed.Load() {
		select {
		case c.entered <- struct{}{}:
		default:
		}
	}
	return c.Conn.Write(b)
}

// net.Pipe has no buffer: a frame write cannot complete while the opposite
// endpoint intentionally stops reading. Close must release the blocked writer.
func TestCanonicalTCPBackpressureClose(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(method+"/"+direction, func(t *testing.T) {
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				a.SetDeadline(time.Now().Add(5 * time.Second))
				b.SetDeadline(time.Now().Add(5 * time.Second))
				observedClient := &writeObservation{Conn: a, entered: make(chan struct{}, 1)}
				observedServer := &writeObservation{Conn: b, entered: make(chan struct{}, 1)}
				keys := testKeys(t, method)
				accepted := make(chan *Conn, 1)
				acceptErr := make(chan error, 1)
				go func() {
					c, _, _, err := AcceptTCP(observedServer, keys, nil, NewSaltCache(32, time.Minute), time.Now())
					accepted <- c
					acceptErr <- err
				}()
				client, err := ClientTCP(observedClient, keys, access.Endpoint{Host: "127.0.0.1", Port: 443}, NewSaltCache(32, time.Minute))
				if err != nil {
					t.Fatal(err)
				}
				server := <-accepted
				if err = <-acceptErr; err != nil {
					t.Fatal(err)
				}
				writer, observed := client, observedClient
				if direction == "server" {
					writer, observed = server, observedServer
				}
				observed.armed.Store(true)
				finished := make(chan error, 1)
				go func() { _, err := writer.Write(bytes.Repeat([]byte("bounded frame"), 16384)); finished <- err }()
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				select {
				case <-observed.entered:
				case <-deadline.C:
					t.Fatal("writer did not enter backpressure")
				}
				select {
				case err := <-finished:
					t.Fatal("write completed without a reader", err)
				default:
				}
				if err = writer.Close(); err != nil {
					t.Fatal(err)
				}
				select {
				case err = <-finished:
					if err == nil {
						t.Fatal("closed blocked writer succeeded")
					}
				case <-deadline.C:
					t.Fatal("Close did not join blocked write")
				}
			})
		}
	}
}
