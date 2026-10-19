package session

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/relay"
)

type halfCloseUpload struct {
	data []byte
	err  error
}
type halfCloseTCPFixture struct {
	address string
	upload  chan halfCloseUpload
	tail    chan struct{}
	release sync.Once
}

func halfCloseTarget(t *testing.T) *halfCloseTCPFixture {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	v := &halfCloseTCPFixture{address: l.Addr().String(), upload: make(chan halfCloseUpload, 1), tail: make(chan struct{})}
	var mu sync.Mutex
	var active net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			return
		}
		mu.Lock()
		active = c
		mu.Unlock()
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		data, e := io.ReadAll(c)
		v.upload <- halfCloseUpload{data, e}
		if e != nil {
			return
		}
		// Target responds only after real TCP EOF. Keep its second response write
		// behind a channel released after the client reads the first write.
		if _, e = c.Write([]byte("response-after-EOF:")); e != nil {
			return
		}
		<-v.tail
		if _, e = c.Write(data); e != nil {
			return
		}
		_ = c.(*net.TCPConn).CloseWrite()
	}()
	t.Cleanup(func() {
		l.Close()
		v.release.Do(func() { close(v.tail) })
		mu.Lock()
		if active != nil {
			active.Close()
		}
		mu.Unlock()
		<-done
	})
	return v
}

type halfCloseObservedRequest struct {
	net.Conn
	total int
	eof   chan int
}

func (c *halfCloseObservedRequest) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.total += n
	if e == io.EOF {
		c.eof <- c.total
	}
	return n, e
}
func (c *halfCloseObservedRequest) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func halfCloseExchange(t *testing.T, c *Client, size int, serverEOF <-chan int) {
	t.Helper()
	target := halfCloseTarget(t)
	ctx, cancel := context.WithCancel(context.Background())
	conn, e := c.Open(ctx, target.address)
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	payload := bytes.Repeat([]byte{0x79}, size)
	n, e := conn.Write(payload)
	if e != nil || n != size {
		t.Fatalf("write=%d/%d error=%v", n, size, e)
	}
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	prefix := make([]byte, len("response-after-EOF:"))
	if _, e = io.ReadFull(conn, prefix); e != nil {
		t.Fatal("response prefix after half-close", e)
	}
	if string(prefix) != "response-after-EOF:" {
		t.Fatal("response prefix integrity")
	}
	// Idempotent completion must neither write another frame nor cancel reading.
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal("second CloseWrite", e)
	}
	var uploaded halfCloseUpload
	select {
	case uploaded = <-target.upload:
	case <-time.After(15 * time.Second):
		t.Fatal("target did not observe EOF")
	}
	if uploaded.err != nil || !bytes.Equal(uploaded.data, payload) {
		t.Fatalf("target upload=%d/%d error=%v", len(uploaded.data), size, uploaded.err)
	}
	if serverEOF != nil {
		select {
		case n := <-serverEOF:
			if n != size {
				t.Fatalf("server request EOF bytes=%d want=%d", n, size)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("server request reader did not receive EOF")
		}
	}
	target.release.Do(func() { close(target.tail) })
	response, e := io.ReadAll(conn)
	if e != nil || !bytes.Equal(response, payload) {
		t.Fatalf("response tail=%d/%d error=%v", len(response), size, e)
	}
}

func TestClientSendHalfLifecycle(t *testing.T) {
	for _, mode := range []string{"http3", "http2"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "http3" && !H3Enabled() {
				t.Skip("QUIC disabled")
			}
			requestEOF := make(chan int, 1)
			address, tc, _ := startServer(t, mode, func(cfg *ServerConfig) {
				cfg.Relay = func(ctx context.Context, _ string, a, b net.Conn) {
					relay.Join(ctx, &halfCloseObservedRequest{Conn: a, eof: requestEOF}, b)
				}
			})
			c := newClient(t, mode, address, tc, nil)
			for _, size := range []int{1, 2, 1024, 16383, 16384, 16385} {
				t.Run(fmt.Sprint(size), func(t *testing.T) { halfCloseExchange(t, c, size, requestEOF) })
			}
		})
	}
}
