package netbench

import (
	"net"
	"sync"
	"testing"
	"time"
)

// Targets owns its listeners and every accepted socket, and joins all workers.
// It generates/checks real application bytes on OS sockets.
func Targets(t testing.TB, host string, timeout time.Duration) (net.Addr, net.Addr) {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		l.Close()
		t.Fatal(err)
	}
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	closed := false
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				c.Close()
				return
			}
			active[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(timeout))
				_ = ServeTCP(c)
			}()
		}
	}()
	go func() {
		defer wg.Done()
		b := make([]byte, 65535)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			if _, e = p.WriteTo(b[:n], a); e != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		l.Close()
		p.Close()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l.Addr(), p.LocalAddr()
}
