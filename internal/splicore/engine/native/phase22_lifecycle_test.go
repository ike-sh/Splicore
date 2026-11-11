//go:build with_utls

package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func phaseSOCKS(proxy, dst access.Endpoint) (net.Conn, error) {
	c, e := net.DialTimeout("tcp", net.JoinHostPort(proxy.Host, portString(proxy.Port)), 5*time.Second)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = c.Write([]byte{5, 1, 0}); e != nil {
		return nil, e
	}
	var h [2]byte
	if _, e = io.ReadFull(c, h[:]); e != nil {
		return nil, e
	}
	if h != [2]byte{5, 0} {
		return nil, errors.New("SOCKS authentication rejected")
	}
	ip := net.ParseIP(dst.Host).To4()
	if ip == nil {
		return nil, errors.New("fixture destination must be IPv4")
	}
	q := append([]byte{5, 1, 0, 1}, ip...)
	q = binary.BigEndian.AppendUint16(q, dst.Port)
	if _, e = c.Write(q); e != nil {
		return nil, e
	}
	var reply [4]byte
	if _, e = io.ReadFull(c, reply[:]); e != nil {
		return nil, e
	}
	if reply[0] != 5 || reply[1] != 0 {
		return nil, errors.New("SOCKS request rejected")
	}
	n := 0
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var b [1]byte
		if _, e = io.ReadFull(c, b[:]); e != nil {
			return nil, e
		}
		n = int(b[0])
	default:
		return nil, errors.New("invalid SOCKS address")
	}
	if _, e = io.CopyN(io.Discard, c, int64(n+2)); e != nil {
		return nil, e
	}
	ok = true
	return c, nil
}

// The target half-closes its response before the client half-closes its upload.
// Both halves must drain; this detects wrappers that turn EOF into full Close.
func phaseHalfServer(t *testing.T) (access.Endpoint, <-chan []byte, <-chan struct{}) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	reply := make(chan []byte, 1)
	ready := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	var mu sync.Mutex
	var accepted net.Conn
	go func() {
		defer wg.Done()
		c, e := l.Accept()
		if e != nil {
			return
		}
		mu.Lock()
		accepted = c
		mu.Unlock()
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		_, e = c.Write([]byte("server-half-close"))
		if e == nil {
			e = c.(*net.TCPConn).CloseWrite()
		}
		if e != nil {
			close(ready)
			reply <- nil
			return
		}
		close(ready)
		b, e := io.ReadAll(c)
		if e != nil {
			b = nil
		}
		reply <- b
	}()
	t.Cleanup(func() {
		l.Close()
		mu.Lock()
		if accepted != nil {
			accepted.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return netaddrEndpoint(l.Addr()), reply, ready
}
func TestPhase22NativeServerHalfCloseDeadlineCancellation(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, p := range phaseProfiles() {
		t.Run(p.name, func(t *testing.T) {
			in, n, cred := phaseFixture(t, p)
			h := sharedPrepare(t, ctx, "vless", in)
			if e := h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			defer h.Close(context.Background())
			d := sharedBuild(t, ctx, n, cred)
			defer d.Close()
			dst, ch, ready := phaseHalfServer(t)
			c, e := d.DialContext(ctx, dst)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			got, e := io.ReadAll(c)
			if e != nil || string(got) != "server-half-close" {
				t.Fatal("server half", e)
			}
			payload := bytes.Repeat([]byte("upload after response EOF"), 8192)
			<-ready
			if _, e = c.Write(payload); e != nil {
				t.Fatal(e)
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if got := <-ch; !bytes.Equal(got, payload) {
				t.Fatal("upload did not drain")
			}
			echo := vlessEcho(t, nil)
			c, e = d.DialContext(ctx, netaddrEndpoint(echo.Addr()))
			if e != nil {
				t.Fatal(e)
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			var b [1]byte
			if _, e = c.Read(b[:]); e == nil {
				t.Fatal("read deadline ignored")
			}
			c.Close()
			cancelCtx, cancel := context.WithCancel(ctx)
			cancel()
			if c, e = d.DialContext(cancelCtx, netaddrEndpoint(echo.Addr())); e == nil {
				c.Close()
				t.Fatal("cancelled dial admitted")
			}
			c, e = d.DialContext(ctx, netaddrEndpoint(echo.Addr()))
			if e != nil {
				t.Fatal(e)
			}
			c.Close() // early EOF before application data
			// Pending Read must end when the runtime closes all connections.
			c, e = d.DialContext(ctx, netaddrEndpoint(echo.Addr()))
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { _, e := c.Read(b[:]); done <- e }()
			d.Close()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("close did not interrupt read")
				}
			case <-time.After(time.Second):
				t.Fatal("read leaked")
			}
		})
	}
}
