package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
)

type memoryConn struct {
	reader   *bytes.Reader
	writer   bytes.Buffer
	fragment int
}

func (c *memoryConn) Read(b []byte) (int, error) {
	if c.fragment > 0 {
		b = b[:min(len(b), c.fragment)]
	}
	return c.reader.Read(b)
}
func (c *memoryConn) Write(b []byte) (int, error)    { return c.writer.Write(b) }
func (*memoryConn) Close() error                     { return nil }
func (*memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (c *memoryConn) RemoteAddr() net.Addr           { return c.LocalAddr() }
func (*memoryConn) SetDeadline(time.Time) error      { return nil }
func (*memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (*memoryConn) SetWriteDeadline(time.Time) error { return nil }
func testKeys(t testing.TB, method string) []*Key {
	t.Helper()
	m, e := ss.Lookup(method)
	if e != nil {
		t.Fatal(e)
	}
	material := "synthetic-password"
	if m.Edition == "2022" {
		material = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{42}, m.KeySize))
	}
	k, e := Keys(method, material)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func TestCanonicalTCPFragmentationReplayAndBounds(t *testing.T) {
	for _, m := range ss.Methods() {
		t.Run(m.Name, func(t *testing.T) {
			keys := testKeys(t, m.Name)
			dst := access.Endpoint{Host: "synthetic.example", Port: 443}
			record := &memoryConn{reader: bytes.NewReader(nil)}
			client, e := ClientTCP(record, keys, dst, NewSaltCache(32, time.Minute))
			if e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte("fragment"), 10000)
			client.Write(payload)
			stream := bytes.Clone(record.writer.Bytes())
			for _, fragment := range []int{0, 1, 7, 29} {
				raw := &memoryConn{reader: bytes.NewReader(stream), fragment: fragment}
				if m.Edition == "2022" {
					raw.fragment = 0
				}
				server, got, _, e := AcceptTCP(raw, keys, nil, NewSaltCache(32, time.Minute), time.Now())
				if e != nil || got != dst {
					t.Fatal("accept", e)
				}
				raw.fragment = fragment
				b := make([]byte, len(payload))
				if _, e = io.ReadFull(server, b); e != nil || !bytes.Equal(b, payload) {
					t.Fatal("fragmented payload", e)
				}
				if _, e = server.Write(payload); e != nil {
					t.Fatal(e)
				}
				client.reader = nil
				client.rnonce = [12]byte{}
				client.pending = nil
				record.reader = bytes.NewReader(bytes.Clone(raw.writer.Bytes()))
				if _, e = io.ReadFull(client, b); e != nil || !bytes.Equal(b, payload) {
					t.Fatal("response", e)
				}
			}
			replay := NewSaltCache(32, time.Minute)
			for attempt := range 2 {
				_, _, _, e = AcceptTCP(&memoryConn{reader: bytes.NewReader(stream)}, keys, nil, replay, time.Now())
				if attempt == 0 && e != nil || attempt == 1 && !errors.Is(e, ErrReplay) {
					t.Fatal("TCP replay", attempt, e)
				}
			}
			if m.Edition == "2022" {
				if _, _, _, e = AcceptTCP(&memoryConn{reader: bytes.NewReader(stream), fragment: 1}, keys, nil, NewSaltCache(32, time.Minute), time.Now()); !errors.Is(e, ErrFrame) {
					t.Fatal("short initial header accepted")
				}
			}
		})
	}
	key := testKeys(t, "aes-128-gcm")[0]
	salt := bytes.Repeat([]byte{1}, 16)
	aead, _ := key.aead(salt)
	nonce := make([]byte, 12)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], 65535)
	stream := append(bytes.Clone(salt), aead.Seal(nil, nonce, length[:], nil)...)
	if _, _, _, e := AcceptTCP(&memoryConn{reader: bytes.NewReader(stream)}, []*Key{key}, nil, NewSaltCache(32, time.Minute), time.Now()); !errors.Is(e, ErrFrame) {
		t.Fatal("oversized classic length accepted", e)
	}
}
func TestUDPReplayTimestampIdentityAndEdges(t *testing.T) {
	for _, m := range ss.Methods() {
		keys := testKeys(t, m.Name)
		for _, dst := range []access.Endpoint{{Host: "127.0.0.1", Port: 1234}, {Host: "::1", Port: 1234}, {Host: "synthetic.example", Port: 53}} {
			for _, size := range []int{0, 1, 32000} {
				now := time.Now()
				p := Datagram{Session: 42, Packet: 7, Destination: dst, Payload: bytes.Repeat([]byte{9}, size)}
				raw, e := EncodePacket(keys, p, false, now)
				if e != nil {
					t.Fatal(e)
				}
				got, e := DecodePacket(keys, nil, raw, false, 0, NewSaltCache(32, time.Minute), now)
				if e != nil || got.Destination != dst || !bytes.Equal(got.Payload, p.Payload) {
					t.Fatal("UDP roundtrip", m.Name, e)
				}
				if m.Edition == "2022" {
					if _, e = DecodePacket(keys, nil, raw, false, 0, NewSaltCache(32, time.Minute), now.Add(31*time.Second)); !errors.Is(e, ErrTimestamp) {
						t.Fatal("timestamp", e)
					}
					r := NewUDPReplay(1)
					if e = r.Check(keys[0], got, now); e != nil {
						t.Fatal(e)
					}
					if e = r.Check(keys[0], got, now); !errors.Is(e, ErrReplay) {
						t.Fatal("replay", e)
					}
					got.Session++
					if e = r.Check(keys[0], got, now); !errors.Is(e, ErrCapacity) {
						t.Fatal("replay capacity", e)
					}
					if e = r.Check(keys[0], got, now.Add(91*time.Second)); e != nil {
						t.Fatal("replay expiry", e)
					}
				}
				if m.Identity {
					other := testKeys(t, m.Name)[0]
					other.Material = bytes.Repeat([]byte{43}, m.KeySize)
					chain := []*Key{other, keys[0]}
					raw, e = EncodePacket(chain, p, false, now)
					if e != nil {
						t.Fatal(e)
					}
					got, e = DecodePacket(keys, other, raw, false, 0, NewSaltCache(32, time.Minute), now)
					if e != nil || !bytes.Equal(got.Payload, p.Payload) {
						t.Fatal("identity", e)
					}
				}
			}
		}
	}
	var w Window
	for _, id := range []uint64{9, 7, 8, 1030, math.MaxUint64} {
		if !w.Accept(id) {
			t.Fatal("fresh packet rejected", id)
		}
		w.Commit(id)
		if w.Accept(id) {
			t.Fatal("duplicate accepted")
		}
	}
	now := time.Now()
	if timestampOK(math.MaxUint64, now) || timestampOK(uint64(now.Add(-31*time.Second).Unix()), now) || !timestampOK(uint64(now.Add(30*time.Second).Unix()), now) {
		t.Fatal("timestamp overflow or boundary")
	}
	c := NewSaltCache(1, time.Minute)
	k := testKeys(t, "aes-128-gcm")[0]
	if c.Check(k, []byte{1}, now) != nil || !errors.Is(c.Check(k, []byte{2}, now), ErrCapacity) || c.Check(k, []byte{2}, now.Add(time.Minute)) != nil {
		t.Fatal("salt capacity/expiry")
	}
}
func FuzzShadowsocksTCPFrame(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80}, uint16(7), false)
	f.Add([]byte{3, 255}, uint16(65535), true)
	f.Fuzz(fuzzTCPFrame)
}
func FuzzShadowsocksClassicTCPFrame(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80}, uint16(7))
	f.Fuzz(func(t *testing.T, p []byte, declared uint16) { fuzzTCPFrame(t, p, declared, false) })
}
func FuzzShadowsocks2022TCPFrame(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80}, uint16(7))
	f.Fuzz(func(t *testing.T, p []byte, declared uint16) { fuzzTCPFrame(t, p, declared, true) })
}
func fuzzTCPFrame(t *testing.T, p []byte, declared uint16, modern bool) {
	if len(p) > 65535 {
		return
	}
	method := "aes-128-gcm"
	if modern {
		method = "2022-blake3-aes-128-gcm"
	}
	k := testKeys(t, method)[0]
	salt := bytes.Repeat([]byte{1}, k.Method.KeySize)
	aead, _ := k.aead(salt)
	c := &Conn{Conn: &memoryConn{reader: bytes.NewReader(nil)}, key: k, writer: aead}
	var fixed []byte
	if modern {
		fixed = make([]byte, 11)
		putTime(fixed[1:9], time.Now())
		binary.BigEndian.PutUint16(fixed[9:], declared)
	} else {
		fixed = binary.BigEndian.AppendUint16(nil, declared)
	}
	head, _ := c.seal(fixed)
	data, _ := c.seal(p)
	stream := append(bytes.Clone(salt), head...)
	stream = append(stream, data...)
	_, _, _, _ = AcceptTCP(&memoryConn{reader: bytes.NewReader(stream)}, []*Key{k}, nil, NewSaltCache(4, time.Minute), time.Now())
}
func FuzzShadowsocksUDPDatagram(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80}, false)
	f.Add([]byte{}, true)
	f.Fuzz(fuzzUDPDatagram)
}
func FuzzShadowsocksClassicUDPDatagram(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, p []byte) { fuzzUDPDatagram(t, p, false) })
}
func FuzzShadowsocks2022UDPDatagram(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Fuzz(func(t *testing.T, p []byte) { fuzzUDPDatagram(t, p, true) })
}
func fuzzUDPDatagram(t *testing.T, p []byte, modern bool) {
	if len(p) > 65535 {
		return
	}
	method := "aes-128-gcm"
	if modern {
		method = "2022-blake3-aes-128-gcm"
	}
	keys := testKeys(t, method)
	_, _ = DecodePacket(keys, nil, p, false, 0, NewSaltCache(4, time.Minute), time.Now())
	// Also mutate authenticated plaintext, so the fuzzer reaches address,
	// timestamp and padding validation rather than only the AEAD tag gate.
	salt := bytes.Repeat([]byte{4}, 16)
	if !modern {
		a, _ := keys[0].aead(salt)
		raw := append(salt, a.Seal(nil, make([]byte, 12), p, nil)...)
		_, _ = DecodePacket(keys, nil, raw, false, 0, NewSaltCache(4, time.Minute), time.Now())
	} else {
		a, _ := keys[0].aead(salt[:8])
		block, _ := keys[0].block()
		header := make([]byte, 16)
		block.Encrypt(header, salt)
		raw := append(header, a.Seal(nil, salt[4:], p, nil)...)
		_, _ = DecodePacket(keys, nil, raw, false, 0, NewSaltCache(4, time.Minute), time.Now())
	}
}
func FuzzShadowsocksAddress(f *testing.F) {
	f.Add([]byte{1, 127, 0, 0, 1, 0, 80})
	f.Add([]byte{3, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		dst, _, e := splitAddress(b)
		if e == nil {
			encoded, e := Address(dst)
			if e != nil {
				t.Fatal(e)
			}
			other, _, e := splitAddress(encoded)
			if e != nil || other != dst {
				t.Fatal("address roundtrip")
			}
		}
	})
}
