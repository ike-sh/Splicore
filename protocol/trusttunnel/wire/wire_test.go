package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
)

func TestUDPAsymmetricFrames(t *testing.T) {
	for _, ip := range []string{"192.0.2.3", "::1", "2001:db8::1", "::ffff:192.0.2.3"} {
		for _, size := range []int{0, 1, 1200, 1472, 4048, MaxPayload} {
			for _, out := range []bool{false, true} {
				d := Datagram{Source: netip.AddrPortFrom(netip.MustParseAddr(ip).Unmap(), 1234), Destination: netip.MustParseAddrPort("198.51.100.1:53"), Payload: bytes.Repeat([]byte{byte(size)}, size)}
				if out {
					d.App = "test\x00app"
				}
				b, e := EncodeUDP(d, out)
				if e != nil {
					t.Fatal(e)
				}
				if int(binary.BigEndian.Uint32(b)) != len(b)-4 {
					t.Fatal("length")
				}
				got, e := ReadUDP(bytes.NewReader(b), out)
				if e != nil || got.Source != d.Source || got.Destination != d.Destination || got.App != d.App || !bytes.Equal(got.Payload, d.Payload) {
					t.Fatal(got, e)
				}
				for _, n := range []int{1, 3, len(b) - 1} {
					if _, e := ReadUDP(bytes.NewReader(b[:n]), out); e == nil {
						t.Fatal("truncated", n)
					}
				}
			}
		}
	}
}

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(1, len(p))]) }
func TestUDPStreamSplitsAndAllocationBounds(t *testing.T) {
	d := Datagram{Source: netip.MustParseAddrPort("192.0.2.1:1"), Destination: netip.MustParseAddrPort("[::1]:53")}
	b, _ := EncodeUDP(d, true)
	r := byteReader{bytes.NewReader(append(b, b...))}
	for range 2 {
		if _, e := ReadUDP(r, true); e != nil {
			t.Fatal(e)
		}
	}
	for _, n := range []uint32{0, 35, 36, MaxFrame + 1, 0xffffffff} {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		if _, e := ReadUDP(bytes.NewReader(b[:]), true); e == nil {
			t.Fatal(n)
		}
	}
}
func TestAuthorityAndBasic(t *testing.T) {
	for _, a := range []string{"example.test:443", "127.0.0.1:1", "[::1]:443", "[::ffff:127.0.0.1]:443"} {
		if _, e := Authority(a); e != nil {
			t.Fatal(a, e)
		}
	}
	for _, a := range []string{"host", "host:0", "host:65536", "host:00443", "::1:443", ":1", "a b:1", "a\r:1", "a@b:1", "https://a:1", "_udp2:123", "_check:0", "[::ffff:0.0.0.0]:80", "[::ffff:224.0.0.1]:80", "2130706433:80", "127.1:80", "[fe80::1%lo]:80"} {
		if _, e := Authority(a); e == nil {
			t.Fatal(a)
		}
	}
	u, p, e := Basic(Authorization("user", "pass:word"))
	if e != nil || u != "user" || p != "pass:word" {
		t.Fatal(e)
	}
	for _, b := range []string{"", "Basic ?", "Basic Og==", "Basic dXNlcjo="} {
		if _, _, e := Basic(b); e == nil {
			t.Fatal("accepted bad auth")
		}
	}
}
func TestICMPExactFixedLength(t *testing.T) {
	r := EchoRequest{42, netip.MustParseAddr("::1"), 65535, 64, 4048}
	b, e := EncodeEchoRequest(r)
	if e != nil || len(b) != 23 {
		t.Fatal(e)
	}
	v, e := DecodeEchoRequest(b)
	if e != nil || v != r {
		t.Fatal(e)
	}
	reply := EchoReply{42, r.Destination, 129, 0, r.Sequence}
	b, e = EncodeEchoReply(reply)
	if e != nil || len(b) != 22 {
		t.Fatal(e)
	}
	got, e := DecodeEchoReply(b)
	if e != nil || got != reply {
		t.Fatal(e)
	}
	if _, e = DecodeEchoRequest(b); e == nil {
		t.Fatal("asymmetric layout accepted")
	}
}
func FuzzUDP(f *testing.F) {
	for _, b := range [][]byte{{}, {0, 0, 0, 37}, bytes.Repeat([]byte{0xff}, 64)} {
		f.Add(b, true)
	}
	f.Fuzz(func(t *testing.T, b []byte, out bool) {
		if len(b) > MaxFrame+4 {
			return
		}
		d, e := ReadUDP(bytes.NewReader(b), out)
		if e == nil {
			encoded, e := EncodeUDP(d, out)
			if e != nil {
				t.Fatal(e)
			}
			got, e := ReadUDP(bytes.NewReader(encoded), out)
			if e != nil || got.Source != d.Source || got.Destination != d.Destination || !bytes.Equal(got.Payload, d.Payload) {
				t.Fatal("round trip")
			}
		}
	})
}
func FuzzICMP(f *testing.F) {
	f.Add(make([]byte, 23))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, e := DecodeEchoRequest(b); e == nil {
			got, e := EncodeEchoRequest(v)
			canonical, ce := DecodeEchoRequest(got)
			if e != nil || ce != nil || canonical != v {
				t.Fatal("request roundtrip")
			}
		}
		if v, e := DecodeEchoReply(b); e == nil {
			if _, e := EncodeEchoReply(v); e != nil {
				t.Fatal(e)
			}
		}
	})
}
func FuzzAuthorityBasic(f *testing.F) {
	f.Add("example.com:443")
	f.Add("Basic dXNlcjpwYXNz")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		if a, e := Authority(s); e == nil {
			if _, e := Authority(a); e != nil {
				t.Fatal(e)
			}
		}
		if u, p, e := Basic(s); e == nil {
			if _, _, e := Basic(Authorization(u, p)); e != nil {
				t.Fatal(e)
			}
		}
	})
}
