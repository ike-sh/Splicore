//go:build with_quic

package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	quic "github.com/metacubex/jls-quic-go"
)

func cmd4Client(t *testing.T, a net.Addr) *Client {
	t.Helper()
	c, err := NewClient(ClientConfig{ServerName: testName, User: User{Username: testUser, Password: testPassword}, Socket: testSocket(a), UDPOverStream: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestCMD4ConcurrentAssociationsAndCleanup(t *testing.T) {
	_, a, _ := testServer(t, Limits{})
	c := cmd4Client(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			host := "127.0.0.1"
			if i%2 == 0 {
				host = "::1"
			}
			dst := access.Endpoint{Host: host, Port: uint16(9000 + i)}
			p, err := c.OpenPacket(ctx, dst)
			if err != nil {
				t.Error(err)
				return
			}
			defer p.Close()
			_ = p.SetDeadline(time.Now().Add(5 * time.Second))
			for _, size := range []int{0, 1, MaxPayload, 33} {
				want := bytes.Repeat([]byte{byte(i + 1)}, size)
				if _, err = p.WriteTo(want, netaddr.UDP(dst)); err != nil {
					t.Error(err)
					return
				}
				got := make([]byte, MaxPayload)
				n, peer, err := p.ReadFrom(got)
				if err != nil || !bytes.Equal(got[:n], want) || peer.String() != netaddr.UDP(dst).String() {
					t.Error("isolated payload", size, peer, err)
					return
				}
			}
			if _, err = p.WriteTo(make([]byte, MaxPayload+1), netaddr.UDP(dst)); !errors.Is(err, ErrLimit) {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if err := streamBytes(ctx, c, access.Endpoint{Host: "127.0.0.1", Port: 80}, 4096, true); err != nil {
		t.Fatal("TCP sibling", err)
	}
	state := c.current
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.packets) != 0 || len(state.receive) != 0 || len(state.uni) != 0 || len(state.uniIDs) != 0 || len(state.allocated) != 0 {
		t.Fatal("retained CMD4 resources")
	}
}

func TestCMD4MalformedStreamDoesNotBreakSibling(t *testing.T) {
	_, a, _ := testServer(t, Limits{})
	c := cmd4Client(t, a)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{{0}, {234, 96, 255, 255}, {255, 255, 0, 0}} {
		st, err := s.conn.OpenUniStreamSync(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = st.Write(data)
		_ = st.Close()
	}
	dst := access.Endpoint{Host: "::1", Port: 53}
	p, err := c.OpenPacket(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := p.WriteTo([]byte("independent"), netaddr.UDP(dst)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 32)
	n, _, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "independent" {
		t.Fatal(n, err)
	}
	// A known CMD4 mapping with an oversized length resets its payload stream.
	ctrl, err := s.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	h, _ := command(associateStream, access.Endpoint{Host: "0.0.0.0"})
	m, _ := mapping(dst, 50000)
	_, _ = ctrl.Write(append(h, m...))
	st, err := s.conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame := binary.BigEndian.AppendUint16(nil, 50000)
	frame = append(frame, 255, 255)
	_, _ = st.Write(frame)
	_ = st.Close()
	if err := streamBytes(ctx, c, dst, 100, true); err != nil {
		t.Fatal("malformed stream killed TCP", err)
	}
}

func TestCMD4MappingReorderDuplicateAndWrongMode(t *testing.T) {
	for _, overStream := range []bool{true, false} {
		t.Run(map[bool]string{true: "CMD4", false: "CMD3"}[overStream], func(t *testing.T) {
			server, a, _ := testServer(t, Limits{})
			c := testClient(t, a, Limits{})
			c.config.UDPOverStream = overStream
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dst := access.Endpoint{Host: "127.0.0.1", Port: 53}
			pc, err := c.OpenPacket(ctx, dst)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			p := pc.(*packet)
			var peer *quic.Conn
			for until := time.Now().Add(time.Second); time.Now().Before(until); {
				server.mu.Lock()
				for q := range server.connections {
					peer = q
				}
				server.mu.Unlock()
				if peer != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if peer == nil {
				t.Fatal("authenticated peer missing")
			}
			id := uint16(60000)
			frame := binary.BigEndian.AppendUint16(nil, id)
			frame = binary.BigEndian.AppendUint16(frame, 5)
			frame = append(frame, []byte("first")...)
			st, err := peer.OpenUniStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer st.CancelWrite(0)
			if _, err = st.Write(frame); err != nil {
				t.Fatal(err)
			}
			// Observe payload-stream admission before publishing its control mapping.
			for until := time.Now().Add(time.Second); ; {
				p.conn.mu.Lock()
				n := len(p.conn.uni)
				p.conn.mu.Unlock()
				if n > 0 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("payload did not arrive before mapping")
				}
				time.Sleep(time.Millisecond)
			}
			if err = p.conn.register(p, dst, id); err != nil {
				t.Fatal(err)
			}
			_ = p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			b := make([]byte, 16)
			n, _, err := p.ReadFrom(b)
			if overStream {
				if err != nil || string(b[:n]) != "first" {
					t.Fatal("reordered mapping lost payload", err)
				}
			} else if err == nil {
				t.Fatal("CMD3 consumed unistream payload")
			}
			if err = p.conn.register(p, dst, id); err != nil {
				t.Fatal("identical mapping rejected", err)
			}
			if err = p.conn.register(p, access.Endpoint{Host: "127.0.0.1", Port: 54}, id); err == nil {
				t.Fatal("conflicting mapping accepted")
			}
			if overStream {
				dup, err := peer.OpenUniStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = dup.Write(frame)
				_ = dup.Close()
				// A DATAGRAM using a CMD4 mapping must not cross into its stream queue.
				_ = peer.SendDatagram(append(binary.BigEndian.AppendUint16(nil, id), []byte("wrong")...))
				_ = p.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				if _, _, err = p.ReadFrom(b); err == nil {
					t.Fatal("duplicate or wrong-mode payload admitted")
				}
			}
			if err = streamBytes(ctx, c, dst, 1024, true); err != nil {
				t.Fatal("invalid stream killed TCP sibling", err)
			}
		})
	}
}

func TestCMD4IPv6Underlay(t *testing.T) {
	_, a, _ := testServer(t, Limits{}, true)
	c, err := NewClient(ClientConfig{ServerName: testName, User: User{Username: testUser, Password: testPassword}, UDPOverStream: true, Socket: func(context.Context) (net.PacketConn, net.Addr, error) {
		p, err := net.ListenPacket("udp6", "[::1]:0")
		return p, a, err
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dst := access.Endpoint{Host: "::1", Port: 53}
	pc, err := c.OpenPacket(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(time.Second))
	if _, err = pc.WriteTo([]byte("IPv6 CMD4"), netaddr.UDP(dst)); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, _, err := pc.ReadFrom(b)
	if err != nil || string(b[:n]) != "IPv6 CMD4" {
		t.Fatal("IPv6 payload", err)
	}
	if err = streamBytes(ctx, c, dst, 4096, true); err != nil {
		t.Fatal(err)
	}
}
