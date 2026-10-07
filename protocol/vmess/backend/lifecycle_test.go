package backend

import (
	"bytes"
	"context"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func await(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not join")
		return nil
	}
}

type barrierConn struct {
	net.Conn
	write, read  chan struct{}
	wonce, ronce sync.Once
}

func (c *barrierConn) Write(b []byte) (int, error) {
	c.wonce.Do(func() { close(c.write) })
	return c.Conn.Write(b)
}
func (c *barrierConn) Read(b []byte) (int, error) {
	c.ronce.Do(func() { close(c.read) })
	return c.Conn.Read(b)
}
func barrier(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("I/O barrier not reached")
	}
}
func socket(t *testing.T, ctx context.Context, udp bool) (*Conn, *barrierConn, net.Conn, access.Endpoint) {
	t.Helper()
	a, b := net.Pipe()
	dst := access.Endpoint{Host: "127.0.0.1", Port: 53}
	command := wire.TCP
	if udp {
		command = wire.UDP
	}
	r, err := wire.NewRequest(dst, command, wire.AESGCM, wire.ChunkStream|wire.LengthMask|wire.GlobalPadding, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := &barrierConn{Conn: a, write: make(chan struct{}), read: make(chan struct{})}
	c, err := newConn(ctx, raw, r, false)
	if err != nil {
		t.Fatal(err)
	}
	c.readHeader = true
	t.Cleanup(func() { _ = c.Close(); _ = b.Close() })
	return c, raw, b, dst
}
func TestVMTCP_L1_Close(t *testing.T) {
	c, raw, _, _ := socket(t, context.Background(), false)
	write := make(chan error, 1)
	read := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); write <- err }()
	go func() { _, err := c.Read(make([]byte, 64)); read <- err }()
	barrier(t, raw.write)
	barrier(t, raw.read)
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	if await(t, done) != nil || await(t, write) == nil || await(t, read) == nil {
		t.Fatal("close did not interrupt I/O")
	}
}
func TestVMTCP_L2_LiveDeadline(t *testing.T) {
	c, raw, _, _ := socket(t, context.Background(), false)
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); done <- err }()
	barrier(t, raw.write)
	_ = c.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
	if err := await(t, done); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("deadline", err)
	}
	_ = c.SetWriteDeadline(time.Time{})
	if _, err := c.Write([]byte("after")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed frame owner reused", err)
	}
}
func TestVMTCP_L5_ParentClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, raw, _, _ := socket(t, ctx, false)
	done := make(chan error, 1)
	go func() { _, err := c.Write([]byte("blocked")); done <- err }()
	barrier(t, raw.write)
	cancel()
	if await(t, done) == nil {
		t.Fatal("parent did not interrupt")
	}
	if c.Close() != nil {
		t.Fatal("parent join")
	}
}

type partialConn struct {
	net.Conn
	calls int
	err   error
	short bool
}

func TestVMTCP_L3_PartialRequest(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	r, _ := wire.NewRequest(access.Endpoint{Host: "127.0.0.1", Port: 80}, wire.TCP, wire.AESGCM, wire.ChunkStream, nil)
	raw := &partialConn{Conn: a, err: io.ErrUnexpectedEOF}
	c, err := Client(context.Background(), raw, wire.Key{1}, r, time.Now())
	if err == nil || c != nil || raw.calls != 1 {
		t.Fatal("partial request published")
	}
	if _, err := a.Write([]byte("next")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("request socket survived", err)
	}
}

func (c *partialConn) Write(b []byte) (int, error) {
	c.calls++
	if c.short {
		return min(3, len(b)), nil
	}
	return min(3, len(b)), c.err
}
func TestVMTCP_L4_PartialFrame(t *testing.T) {
	c, _, _, _ := socket(t, context.Background(), false)
	raw := &partialConn{Conn: c.Conn, err: io.ErrUnexpectedEOF}
	c.Conn = raw
	if _, err := c.Write([]byte("partial")); err == nil {
		t.Fatal("partial failure ignored")
	}
	calls := raw.calls
	if _, err := c.Write([]byte("next")); !errors.Is(err, net.ErrClosed) || raw.calls != calls {
		t.Fatal("tail continued")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	short := &partialConn{Conn: a, short: true}
	if err := writeFull(short, make([]byte, 35)); err != nil || short.calls != 12 {
		t.Fatal("positive short write not completed", err)
	}
}
func TestVMTCP_HalfCloseAndResponse(t *testing.T) {
	for _, mode := range []byte{wire.AESGCM, wire.ChaCha, wire.None} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			a, b := net.Pipe()
			r, _ := wire.NewRequest(access.Endpoint{Host: "::1", Port: 443}, wire.TCP, mode, wire.ChunkStream|wire.LengthMask, nil)
			client, _ := newConn(context.Background(), a, r, false)
			server, _ := Server(context.Background(), b, r)
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() {
				data, err := io.ReadAll(server)
				if err != nil || string(data) != "upload" {
					done <- errors.New("upload EOF failed")
					return
				}
				_, err = server.Write([]byte("response after upload EOF"))
				if err == nil {
					err = server.CloseWrite()
				}
				done <- err
			}()
			if _, err := client.Write([]byte("upload")); err != nil {
				t.Fatal(err)
			}
			if err := client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(client)
			if err != nil || string(data) != "response after upload EOF" {
				t.Fatal("reverse traffic", err)
			}
			if await(t, done) != nil {
				t.Fatal("server half-close")
			}
		})
	}
}
func TestVMUDP_L1_Close(t *testing.T) {
	c, raw, _, dst := socket(t, context.Background(), true)
	p := NewPacket(context.Background(), c, dst)
	done := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("blocked"), netaddr.UDP(dst)); done <- err }()
	barrier(t, raw.write)
	joined := make(chan error, 1)
	go func() { joined <- p.Close() }()
	if await(t, joined) != nil || await(t, done) == nil {
		t.Fatal("packet close join")
	}
}
func TestVMUDP_L2_LiveDeadline(t *testing.T) {
	c, raw, _, dst := socket(t, context.Background(), true)
	p := NewPacket(context.Background(), c, dst)
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("blocked"), netaddr.UDP(dst)); done <- err }()
	barrier(t, raw.write)
	_ = p.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
	if err := await(t, done); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("live packet deadline", err)
	}
	_ = p.SetWriteDeadline(time.Time{})
	if _, err := p.WriteTo([]byte("next"), netaddr.UDP(dst)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("deadline owner reused", err)
	}
}
func TestVMUDP_L5_ParentClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c, raw, _, dst := socket(t, ctx, true)
	p := NewPacket(ctx, c, dst)
	done := make(chan error, 1)
	go func() { _, err := p.WriteTo([]byte("blocked"), netaddr.UDP(dst)); done <- err }()
	barrier(t, raw.write)
	cancel()
	if await(t, done) == nil {
		t.Fatal("packet parent close")
	}
	_ = p.Close()
}
func TestVMUDP_L3_ReaderDeath(t *testing.T) {
	c, raw, peer, dst := socket(t, context.Background(), true)
	p := NewPacket(context.Background(), c, dst)
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 64)); done <- err }()
	barrier(t, raw.read)
	_ = peer.Close()
	if await(t, done) == nil {
		t.Fatal("reader death ignored")
	}
	if _, err := p.WriteTo([]byte("next"), netaddr.UDP(dst)); !errors.Is(err, net.ErrClosed) {
		t.Fatal("dead reply path reused", err)
	}
	// The independently owned sibling remains usable.
	TestVMUDP_DestinationReply(t)
}
func TestVMUDP_PartialFrame(t *testing.T) {
	c, _, _, dst := socket(t, context.Background(), true)
	raw := &partialConn{Conn: c.Conn, err: io.ErrUnexpectedEOF}
	c.Conn = raw
	p := NewPacket(context.Background(), c, dst)
	defer p.Close()
	if _, err := p.WriteTo([]byte("partial"), netaddr.UDP(dst)); err == nil {
		t.Fatal("partial ignored")
	}
	calls := raw.calls
	if _, err := p.WriteTo([]byte("next"), netaddr.UDP(dst)); err == nil || calls != raw.calls {
		t.Fatal("partial stream reused")
	}
}
func TestVMUDP_DestinationReply(t *testing.T) {
	for _, mode := range []byte{wire.AESGCM, wire.ChaCha, wire.None} {
		a, b := net.Pipe()
		dst := access.Endpoint{Host: "example.test", Port: 53}
		r, _ := wire.NewRequest(dst, wire.UDP, mode, wire.ChunkStream|wire.LengthMask, nil)
		client, _ := newConn(context.Background(), a, r, false)
		server, _ := Server(context.Background(), b, r)
		cp := NewPacket(context.Background(), client, dst)
		sp := NewPacket(context.Background(), server, dst)
		if _, err := cp.WriteTo([]byte("wrong"), netaddr.UDP(access.Endpoint{Host: "example.test", Port: 54})); err == nil {
			t.Fatal("destination mismatch")
		}
		if _, err := cp.WriteTo(nil, netaddr.UDP(dst)); err == nil {
			t.Fatal("empty datagram converted to EOF")
		}
		if _, err := cp.WriteTo(make([]byte, wire.MaxChunk+1), netaddr.UDP(dst)); err == nil {
			t.Fatal("oversize segmented")
		}
		done := make(chan error, 1)
		go func() {
			v := make([]byte, 1024)
			n, _, err := sp.ReadFrom(v)
			if err == nil {
				_, err = sp.WriteTo(v[:n], netaddr.UDP(access.Endpoint{Host: "127.0.0.1", Port: dst.Port}))
			}
			done <- err
		}()
		payload := bytes.Repeat([]byte{29}, 800)
		if _, err := cp.WriteTo(payload, netaddr.UDP(dst)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		n, _, err := cp.ReadFrom(buf)
		if err != nil || !bytes.Equal(payload, buf[:n]) {
			t.Fatal("real reply", err)
		}
		if await(t, done) != nil {
			t.Fatal("server packet")
		}
		_ = cp.Close()
		_ = sp.Close()
	}
}
