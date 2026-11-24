package backend

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The real TLS/H2 connection, windows, peer, and streams remain in use. The
// gate models a stalled TCP write after establishment, not a fake HTTP result.
type closeWriteTLSWriteGate struct {
	net.Conn
	armed            atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (g *closeWriteTLSWriteGate) Write(b []byte) (int, error) {
	if g.armed.Load() {
		g.once.Do(func() { close(g.entered) })
		<-g.release
	}
	return g.Conn.Write(b)
}

func TestNaiveH2CloseWriteRejectsCommittedCarrierFailure(t *testing.T) {
	local, remote := net.Pipe()
	carrier := &h2CarrierConn{Conn: local}
	defer carrier.Close()
	readDone := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := carrier.Read(b[:])
		readDone <- err
	}()
	if err := remote.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err == nil {
		t.Fatal("terminal carrier Read succeeded")
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	request := &h2RequestBody{PipeReader: reader}
	if err := h2FinishWrite(context.Background(), request, writer, carrier)(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("CloseWrite after committed carrier failure = %T %v; want net.ErrClosed", err, err)
	}
	request.mu.Lock()
	closed, failed := request.closed, request.failed
	request.mu.Unlock()
	if closed || failed != nil {
		t.Fatalf("test requires lagging per-stream mirrors, got closed=%t failed=%v", closed, failed)
	}
}

func TestNaiveH2CloseWriteIndependentOfCarrierWrite(t *testing.T) {
	proxy, tc, _ := startTestServer(t, "https")
	var gate *closeWriteTLSWriteGate
	client := newTestClient(t, "https", proxy, tc, func(c *ClientConfig) {
		c.Padding = "off"
		dial := c.DialTCP
		c.DialTCP = func(ctx context.Context, n, a string) (net.Conn, error) {
			conn, err := dial(ctx, n, a)
			if err != nil {
				return nil, err
			}
			gate = &closeWriteTLSWriteGate{Conn: conn, entered: make(chan struct{}), release: make(chan struct{})}
			return gate, nil
		}
	}, nil)
	target := echoTarget(t, "tcp", "127.0.0.1:0")
	a := openNaiveStateContractConn(t, client, target)
	b := openNaiveStateContractConn(t, client, target)
	body := b.(*pooledStream).raw.(*bodyConn)
	startHalf := make(chan struct{})
	finish := body.closeWrite
	body.closeWrite = func() error { close(startHalf); return finish() }
	unblock := sync.OnceFunc(func() { close(gate.release) })
	defer unblock()
	writeDone := make(chan error, 1)
	gate.armed.Store(true)
	go func() { _, e := a.Write([]byte("distinct sibling DATA")); writeDone <- e }()
	halfCloseWait(t, gate.entered)
	halfDone, closeDone := make(chan error, 1), make(chan error, 1)
	go func() { halfDone <- b.CloseWrite() }()
	halfCloseWait(t, startHalf)
	go func() { closeDone <- b.Close() }()
	// Capture before unblocking the actual TLS write. The deadline diagnoses a
	// failure, while the transport gate is the ordering mechanism.
	limit := time.NewTimer(2 * time.Second)
	defer limit.Stop()
	halfResult, localDone := halfDone, body.done
awaitLocal:
	for halfResult != nil || localDone != nil {
		select {
		case err := <-halfResult:
			if err != nil {
				t.Errorf("local CloseWrite failed: %v", err)
			}
			halfResult = nil
		case <-localDone:
			localDone = nil
		case <-limit.C:
			_ = pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
			t.Error("stream B cannot commit close while stream A is stalled in carrier Write")
			break awaitLocal
		}
	}
	unblock()
	if halfResult != nil {
		halfCloseResult(t, halfResult)
	}
	halfCloseResult(t, closeDone)
	halfCloseResult(t, writeDone)
}
