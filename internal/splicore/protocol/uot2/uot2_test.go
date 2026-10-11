package uot2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
)

func TestRequestAndDatagramGoldenAddresses(t *testing.T) {
	for _, tc := range []struct{ host, request, datagram string }{
		{"192.0.2.1", "0101c00002010035", "00c00002010035"},
		{"2001:db8::1", "010420010db80000000000000000000000010035", "0120010db80000000000000000000000010035"},
		{"dns.test", "010308646e732e746573740035", "0208646e732e746573740035"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			dst := access.Endpoint{Host: tc.host, Port: 53}
			r := Request{Connect: true, Destination: dst}
			b, err := MarshalRequest(r)
			if err != nil || hex.EncodeToString(b) != tc.request {
				t.Fatalf("request %x %v", b, err)
			}
			got, err := ReadRequest(bytes.NewReader(b))
			if err != nil || got != r {
				t.Fatal(got, err)
			}
			b, err = datagramAddress(dst)
			if err != nil || hex.EncodeToString(b) != tc.datagram {
				t.Fatalf("datagram %x %v", b, err)
			}
			d, err := readDatagramAddress(bytes.NewReader(b))
			if err != nil || d != dst {
				t.Fatal(d, err)
			}
		})
	}
}
func TestPacketConnectedAndNonconnectedBoundaries(t *testing.T) {
	for _, connect := range []bool{false, true} {
		t.Run(map[bool]string{false: "nonconnected", true: "connected"}[connect], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			ready := make(chan *Packet, 1)
			go func() {
				p, err := Server(b)
				if err != nil {
					ready <- nil
				} else {
					ready <- p
				}
			}()
			dst := access.Endpoint{Host: "192.0.2.1", Port: 53}
			c, err := Client(a, Request{Connect: connect, Destination: dst})
			if err != nil {
				t.Fatal(err)
			}
			s := <-ready
			if s == nil {
				t.Fatal("request")
			}
			for _, n := range []int{0, 1, 512, 4096, 65535} {
				data := bytes.Repeat([]byte{byte(n)}, n)
				done := make(chan error, 1)
				go func() { _, err := c.WriteTo(data, netaddr.UDP(dst)); done <- err }()
				buf := make([]byte, n)
				nr, addr, err := s.ReadFrom(buf)
				if err != nil || nr != n || !bytes.Equal(buf, data) || addr.String() != netaddr.UDP(dst).String() {
					t.Fatal(n, nr, addr, err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				go func() { _, err := s.WriteTo(data, netaddr.UDP(dst)); done <- err }()
				nr, _, err = c.ReadFrom(buf)
				if err != nil || nr != n || !bytes.Equal(buf, data) {
					t.Fatal(n, err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			}
			if _, err = c.WriteTo(make([]byte, 65536), netaddr.UDP(dst)); !errors.Is(err, io.ErrShortBuffer) {
				t.Fatal(err)
			}
			if connect {
				if _, err = c.WriteTo(nil, netaddr.UDP(access.Endpoint{Host: "192.0.2.2", Port: 53})); err == nil {
					t.Fatal("changed connected target")
				}
			}
		})
	}
}

type scriptedConn struct{ *bytes.Reader }

func (c scriptedConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c scriptedConn) Close() error                     { return nil }
func (c scriptedConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c scriptedConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c scriptedConn) SetWriteDeadline(time.Time) error { return nil }

func TestCoalescedDatagramsShortBufferConsumesAndMalformed(t *testing.T) {
	dst := access.Endpoint{Host: "127.0.0.1", Port: 53}
	p := &Packet{conn: scriptedConn{bytes.NewReader([]byte{0, 3, 1, 2, 3, 0, 0, 0, 1, 9})}, request: Request{Connect: true, Destination: dst}}
	buf := make([]byte, 1)
	if n, _, err := p.ReadFrom(buf); n != 1 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(n, err)
	}
	if n, _, err := p.ReadFrom(buf); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if n, _, err := p.ReadFrom(buf); n != 1 || err != nil || buf[0] != 9 {
		t.Fatal(n, err)
	}
	valid, _ := MarshalRequest(Request{Connect: true, Destination: dst})
	for i := 0; i < len(valid); i++ {
		if _, err := ReadRequest(bytes.NewReader(valid[:i])); err == nil {
			t.Fatal("truncated request", i)
		}
	}
	for _, bad := range [][]byte{{2}, {1, 9}, {0, 1, 0, 0, 0}, {1, 1, 127, 0, 0, 1, 0, 0}} {
		if _, err := ReadRequest(bytes.NewReader(bad)); err == nil {
			t.Fatal("bad request", bad)
		}
	}
	for _, bad := range [][]byte{{9}, {0, 127, 0}, {2, 0, 0, 53}} {
		if _, err := readDatagramAddress(bytes.NewReader(bad)); err == nil {
			t.Fatal("bad address", bad)
		}
	}
	p = &Packet{conn: scriptedConn{bytes.NewReader([]byte{0, 2, 1})}, request: Request{Connect: true, Destination: dst}}
	if _, _, err := p.ReadFrom(make([]byte, 4)); err == nil {
		t.Fatal("truncated datagram")
	}
}
