package streamtransport

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func httpStreamPair(t *testing.T, cl *Client, l net.Listener) (net.Conn, net.Conn) {
	t.Helper()
	a, e := cl.DialContext(t.Context())
	if e != nil {
		t.Fatal(e)
	}
	b, e := l.Accept()
	if e != nil {
		a.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(5 * time.Second))
	b.SetDeadline(time.Now().Add(5 * time.Second))
	return a, b
}

func awaitHTTPResult(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP operation blocked")
	}
}

func TestPhase31HTTPConcurrentWriteIntegrity(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, _ := httpFixture(t, kind)
			for _, size := range []int{1, 1024, 256 << 10} {
				t.Run(fmt.Sprint(size), func(t *testing.T) {
					a, b := httpStreamPair(t, cl, l)
					const writers = 2
					const blocks = 16
					received := make(chan error, 1)
					go func() {
						seen := [writers * blocks]bool{}
						block := make([]byte, size)
						for range writers * blocks {
							if _, e := io.ReadFull(a, block); e != nil {
								received <- e
								return
							}
							id := int(block[0])
							if id >= len(seen) || seen[id] || !bytes.Equal(block, bytes.Repeat([]byte{byte(id)}, size)) {
								received <- fmt.Errorf("corrupt, duplicate or interleaved block %d", id)
								return
							}
							seen[id] = true
						}
						received <- nil
					}()
					start := make(chan struct{})
					done := make(chan error, writers)
					for writer := range writers {
						go func() {
							<-start
							for i := range blocks {
								p := bytes.Repeat([]byte{byte(writer*blocks + i)}, size)
								if n, e := b.Write(p); e != nil || n != len(p) {
									done <- fmt.Errorf("write %d: %d %v", i, n, e)
									return
								}
							}
							done <- nil
						}()
					}
					close(start)
					for range writers {
						awaitHTTPResult(t, done)
					}
					awaitHTTPResult(t, received)
					// No missing/extra response bytes: completion only after every unique block.
					if e := a.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
						t.Fatal(e)
					}
					if _, e := io.Copy(io.Discard, b); e != nil {
						t.Fatal(e)
					}
					if e := b.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
						t.Fatal(e)
					}
					tail, e := io.ReadAll(a)
					if e != nil || len(tail) != 0 {
						t.Fatal("response tail", len(tail), e)
					}
				})
			}
		})
	}
}

// This gate surrounds the real Write+Flush, retaining actual HTTP transport
// cancellation. It makes queued-write and unrelated-stream progress assertions
// independent of socket buffer sizes and scheduling delays.
type gatedHTTPWriter struct {
	writer  io.Writer
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (w *gatedHTTPWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.resume })
	return w.writer.Write(p)
}

func TestPhase31HTTPWriteCloseAndParallelStreams(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, count := httpFixture(t, kind)
			a, b := httpStreamPair(t, cl, l)
			body := b.(*httpBodyConn)
			gate := &gatedHTTPWriter{writer: body.writer, entered: make(chan struct{}), resume: make(chan struct{})}
			body.writer = gate
			release := sync.OnceFunc(func() { close(gate.resume) })
			defer release()
			done := make(chan error, 2)
			go func() { _, e := b.Write(bytes.Repeat([]byte{91}, 16<<20)); done <- e }()
			select {
			case <-gate.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("writer never entered")
			}
			// A separate H2 stream / H1 connection exchanges distinguishable data while
			// the first stream holds its write lock.
			nativeEcho(t, cl, l, []byte("independent interactive stream"))
			expected := int32(1)
			if kind == "http" {
				expected = 2
			}
			if count.Load() != expected {
				t.Fatal("physical connection count", count.Load())
			}
			// Reads on the locked stream must also progress.
			reverse := make(chan error, 1)
			go func() { _, e := a.Write([]byte("upload")); reverse <- e }()
			got := make([]byte, 6)
			if _, e := io.ReadFull(b, got); e != nil || string(got) != "upload" {
				t.Fatal(string(got), e)
			}
			awaitHTTPResult(t, reverse)
			go func() { _, e := b.Write([]byte("queued")); done <- e }()
			closed := make(chan error, 1)
			go func() { closed <- b.Close() }()
			awaitHTTPResult(t, closed) // Must not wait behind the held write lock.
			release()
			for range 2 {
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("write survived close")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("write remained blocked after close")
				}
			}
			if _, e := b.Write([]byte{1}); e == nil {
				t.Fatal("write after close")
			}
			nativeEcho(t, cl, l, []byte("after cancellation"))
		})
	}
}

func TestPhase31HTTPNetworkWriteCancellation(t *testing.T) {
	for _, kind := range []string{"http", "h2"} {
		t.Run(kind, func(t *testing.T) {
			cl, l, _ := httpFixture(t, kind)
			a, b := httpStreamPair(t, cl, l)
			body := b.(*httpBodyConn)
			entered := make(chan struct{})
			body.writer = &notifyHTTPWriter{writer: body.writer, entered: entered}
			done := make(chan error, 2)
			for range 2 {
				go func() { _, e := b.Write(bytes.Repeat([]byte{17}, 32<<20)); done <- e }()
			}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("write never started")
			}
			nativeEcho(t, cl, l, []byte("interactive sibling during unread large response"))
			// No reads of the response: cancellation must interrupt real writes and
			// flushes, as well as any writer queued for the stream lock.
			a.Close()
			for range 2 {
				select {
				case e := <-done:
					if e == nil {
						t.Fatal("unread response write completed")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("cancellation did not interrupt writer")
				}
			}
			b.Close()
			nativeEcho(t, cl, l, []byte("healthy after remote cancellation"))
		})
	}
}

type notifyHTTPWriter struct {
	writer  io.Writer
	entered chan struct{}
	once    sync.Once
}

func (w *notifyHTTPWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	return w.writer.Write(p)
}
