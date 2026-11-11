package backend

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNaiveBoundedPoolAndConcurrentUsers(t *testing.T) {
	for _, mode := range []string{"https", "quic"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "quic" && !H3Enabled() {
				t.Skip("with_quic required")
			}
			proxy, tc, _ := startTestServer(t, mode)
			target := echoTarget(t, "tcp", "127.0.0.1:0")
			for _, limit := range []int{2, 4} {
				var count atomic.Int64
				alpha := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.MaxConnections = limit }, &count)
				beta := newTestClient(t, mode, proxy, tc, func(c *ClientConfig) { c.Username = "beta"; c.Password = "beta-pass" }, nil)
				var streams []net.Conn
				for i := 0; i < 8; i++ {
					for _, client := range []*Client{alpha, beta} {
						c, err := client.Open(context.Background(), target)
						if err != nil {
							t.Fatal(err)
						}
						streams = append(streams, c)
					}
				}
				if count.Load() != int64(limit) {
					t.Fatal("connection bound/reuse", count.Load(), limit)
				}
				var wg sync.WaitGroup
				results := make(chan error, len(streams))
				for id, c := range streams {
					wg.Add(1)
					go func() {
						defer wg.Done()
						defer c.Close()
						c.SetDeadline(time.Now().Add(5 * time.Second))
						data := bytes.Repeat([]byte{byte(id)}, 1000+id)
						_, err := c.Write(data)
						if err == nil {
							got := make([]byte, len(data))
							_, err = io.ReadFull(c, got)
							if err == nil && !bytes.Equal(data, got) {
								err = ErrProtocol
							}
						}
						results <- err
					}()
				}
				wg.Wait()
				close(results)
				for err := range results {
					if err != nil {
						t.Fatal(err)
					}
				}
				alpha.Close()
				beta.Close()
			}
		})
	}
}
