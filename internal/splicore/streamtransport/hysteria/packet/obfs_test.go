package packet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"golang.org/x/crypto/blake2b"
)

type datagram struct {
	b []byte
	a net.Addr
}
type capture struct {
	mu     sync.Mutex
	out    []datagram
	closed bool
}

func (c *capture) WriteTo(b []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.out = append(c.out, datagram{bytes.Clone(b), a})
	return len(b), nil
}
func (c *capture) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (c *capture) Close() error                           { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *capture) LocalAddr() net.Addr                    { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (*capture) SetDeadline(time.Time) error              { return nil }
func (*capture) SetReadDeadline(time.Time) error          { return nil }
func (*capture) SetWriteDeadline(time.Time) error         { return nil }

var peer = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

func wrapTest(t *testing.T, kind string) (*Obfs, *capture) {
	t.Helper()
	p := &capture{}
	c, e := Wrap(p, &cfg.HysteriaObfs{Type: kind, Password: "SyntheticObfsSecret"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c.(*Obfs), p
}

func TestSalamanderWireAndOwnership(t *testing.T) {
	c, p := wrapTest(t, "salamander")
	input := bytes.Repeat([]byte{0xC0, 7, 9}, 400)
	original := bytes.Clone(input)
	for range 3 {
		if n, e := c.WriteTo(input, peer); e != nil || n != len(input) {
			t.Fatal(n, e)
		}
	}
	if !bytes.Equal(input, original) {
		t.Fatal("caller buffer modified")
	}
	salts := map[string]bool{}
	for _, d := range p.out {
		if len(d.b) != len(input)+8 {
			t.Fatal("overhead")
		}
		salt := d.b[:8]
		if salts[string(salt)] {
			t.Fatal("salt reused")
		}
		salts[string(salt)] = true
		h := blake2b.Sum256(append([]byte("SyntheticObfsSecret"), salt...))
		plain := make([]byte, len(input))
		for i := range plain {
			plain[i] = d.b[i+8] ^ h[i%32]
		}
		if !bytes.Equal(plain, input) {
			t.Fatal("wire digest")
		}
	}
	for n := 0; n <= 8; n++ {
		if decode("x", make([]byte, n)) {
			t.Fatal("short packet accepted")
		}
	}
}
func TestSalamanderConcurrentWrites(t *testing.T) {
	c, p := wrapTest(t, "salamander")
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 64 {
				b := bytes.Repeat([]byte{byte(worker), byte(i)}, 600)
				if _, e := c.WriteTo(b, peer); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	if len(p.out) != 1024 {
		t.Fatal(len(p.out))
	}
	salts := map[string]bool{}
	for _, d := range p.out {
		if salts[string(d.b[:8])] {
			t.Fatal("salt reused")
		}
		salts[string(d.b[:8])] = true
		if !decode(c.config.Password, d.b) {
			t.Fatal("decode")
		}
	}
}
func TestSalamanderConcurrentReadsClose(t *testing.T) {
	raw, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	receiver, e := Wrap(raw, &cfg.HysteriaObfs{Type: "salamander", Password: "SyntheticObfsSecret"})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	sender, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 128)
			for range 10 {
				n, _, e := receiver.ReadFrom(b)
				if e != nil || n != 32 || !bytes.Equal(b[:n], bytes.Repeat([]byte{7}, 32)) {
					t.Error("concurrent receive", n, e)
					return
				}
			}
		}()
	}
	for range 40 {
		b, e := encode("SyntheticObfsSecret", bytes.Repeat([]byte{7}, 32))
		if e != nil {
			t.Fatal(e)
		}
		sender.WriteTo(b, raw.LocalAddr())
	}
	wg.Wait()
	done := make(chan struct{})
	go func() { defer close(done); b := make([]byte, 128); receiver.ReadFrom(b) }()
	receiver.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close blocked read")
	}
}
func TestGeckoWireReorderDuplicateSources(t *testing.T) {
	c, p := wrapTest(t, "gecko")
	input := bytes.Repeat([]byte{0xC0, 7, 9}, 400)
	if _, e := c.WriteTo(input, peer); e != nil {
		t.Fatal(e)
	}
	if len(p.out) < 2 || len(p.out) > 8 {
		t.Fatal("fragment count")
	}
	other := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 1234}
	var got, otherGot []byte
	for i := len(p.out) - 1; i >= 0; i-- {
		d := p.out[i]
		if len(d.b) < 512 || len(d.b) > 1200 {
			t.Fatal("final UDP size", len(d.b))
		}
		b := bytes.Clone(d.b)
		decode(c.config.Password, b)
		frame := b[:len(b)-8]
		if frame[0] != 0x80 || int(frame[2]&15) != len(p.out) {
			t.Fatal("wire framing")
		}
		if out := c.fragment(frame, peer, time.Now()); out != nil {
			got = out
		}
		if c.fragment(frame, peer, time.Now()) != nil {
			t.Fatal("duplicate delivered")
		}
		if out := c.fragment(frame, other, time.Now()); out != nil {
			otherGot = out
		}
	}
	if !bytes.Equal(got, input) || !bytes.Equal(otherGot, input) {
		t.Fatal("reassembly/source identity")
	}
	before := len(p.out)
	short := []byte{0x40, 1, 2, 3}
	c.WriteTo(short, peer)
	if len(p.out) != before+1 || len(p.out[before].b) != 12 {
		t.Fatal("short header was fragmented")
	}
}
func frame(id, index, total byte, pad int, chunk []byte) []byte {
	b := make([]byte, 5+pad)
	b[0], b[1], b[2] = 0x80, id, index<<4|total
	binary.BigEndian.PutUint16(b[3:5], uint16(pad))
	return append(b, chunk...)
}
func TestGeckoBoundsExpiryConflictWrap(t *testing.T) {
	c, _ := wrapTest(t, "gecko")
	now := time.Now()
	valid := frame(0, 0, 2, 0, []byte{0xC0, 1})
	bad := [][]byte{nil, {0x80}, {0x80, 0, 0x12, 0, 255, 1}, frame(0, 0, 1, 0, []byte{1}), frame(0, 2, 2, 0, []byte{1}), frame(0, 0, 9, 0, []byte{1}), frame(0, 0, 2, 2040, []byte{1})}
	for _, b := range bad {
		if c.fragment(b, peer, now) != nil {
			t.Fatal("malformed delivered")
		}
	}
	c.fragment(valid, peer, now)
	c.fragment(frame(0, 0, 2, 0, []byte{0xC0, 2}), peer, now)
	if c.fragment(frame(0, 1, 2, 0, []byte{3}), peer, now) != nil {
		t.Fatal("conflict revived")
	}
	c.fragment(frame(1, 0, 2, 0, []byte{0xC0}), peer, now)
	c.fragment(frame(1, 1, 3, 0, []byte{3}), peer, now)
	for source := range 1024 {
		a := &net.UDPAddr{IP: net.IPv4(10, byte(source>>8), byte(source), 1), Port: 1234}
		for id := range 256 {
			c.fragment(frame(byte(id), 0, 2, 0, bytes.Repeat([]byte{0xC0}, 100)), a, now)
		}
	}
	c.mu.Lock()
	if len(c.state) > maxMessages || c.buffered > maxBuffered {
		t.Fatal("unbounded state")
	}
	c.expire(now.Add(reassemblyTTL))
	if len(c.state) != 0 || len(c.sources) != 0 || c.buffered != 0 {
		t.Fatal("expired state retained")
	}
	c.mu.Unlock()
	for i := range 512 {
		at := now.Add(time.Duration(i/256+2) * reassemblyTTL)
		id := byte(i)
		c.fragment(frame(id, 0, 2, 0, []byte{0xC0}), peer, at)
		if b := c.fragment(frame(id, 1, 2, 0, []byte{7}), peer, at); !bytes.Equal(b, []byte{0xC0, 7}) {
			t.Fatal("wrap", i)
		}
	}
	c.Close()
	if len(c.state) != 0 || c.buffered != 0 {
		t.Fatal("close retained state")
	}
}
func TestGeckoConcurrentHandshakes(t *testing.T) {
	c, p := wrapTest(t, "gecko")
	var wg sync.WaitGroup
	for worker := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := bytes.Repeat([]byte{0xC0, byte(worker)}, 600)
			if _, e := c.WriteTo(b, peer); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	complete := 0
	for _, d := range p.out {
		b := bytes.Clone(d.b)
		decode(c.config.Password, b)
		if c.fragment(b[:len(b)-8], peer, time.Now()) != nil {
			complete++
		}
	}
	if complete != 32 {
		t.Fatal(complete)
	}
}
func FuzzGeckoFrames(f *testing.F) {
	f.Add(frame(1, 0, 2, 0, []byte{0xC0, 1}))
	f.Add([]byte{0x80, 1, 2})
	f.Fuzz(func(t *testing.T, b []byte) {
		c := &Obfs{state: map[fragmentKey]*message{}, sources: map[string]int{}}
		for i := range 16 {
			c.fragment(b, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: i + 1}, time.Unix(1, 0))
		}
		if len(c.state) > maxMessages || c.buffered > maxBuffered {
			t.Fatal("bound")
		}
	})
}
func FuzzSalamanderDecode(f *testing.F) {
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		original := bytes.Clone(b)
		if decode("synthetic", b) && len(b) <= 8 {
			t.Fatal("short accepted")
		}
		if len(original) > 8 {
			expected := bytes.Clone(original)
			mask := saltMask("synthetic", expected[:8])
			for i := 8; i < len(expected); i++ {
				if b[i-8] != expected[i]^mask[(i-8)%32] {
					t.Fatal(fmt.Sprint(i))
				}
			}
		}
	})
}

// The largest accepted final datagram can devote all but one chunk byte to
// salt, framing and padding. Exercise both receive parsing and configured send.
func TestGeckoMaximumPadding(t *testing.T) {
	c, _ := wrapTest(t, "gecko")
	now := time.Now()
	if out := c.fragment(frame(7, 0, 2, 2034, []byte{0xC0}), peer, now); out != nil {
		t.Fatal("incomplete delivered")
	}
	if out := c.fragment(frame(7, 1, 2, 2034, []byte{9}), peer, now); !bytes.Equal(out, []byte{0xC0, 9}) {
		t.Fatal("maximum padding rejected")
	}
	raw := &capture{}
	pc, e := Wrap(raw, &cfg.HysteriaObfs{Type: "gecko", Password: "SyntheticObfsSecret", MinPacketSize: 2048, MaxPacketSize: 2048})
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	receiver, _ := wrapTest(t, "gecko")
	original := bytes.Repeat([]byte{0xC0, 7}, 600)
	if _, e = pc.WriteTo(original, peer); e != nil {
		t.Fatal(e)
	}
	var reconstructed []byte
	for _, d := range raw.out {
		if len(d.b) != 2048 {
			t.Fatal("final size", len(d.b))
		}
		decode("SyntheticObfsSecret", d.b)
		if out := receiver.fragment(d.b[:len(d.b)-8], peer, now); out != nil {
			reconstructed = out
		}
	}
	if !bytes.Equal(reconstructed, original) {
		t.Fatal("max-size reconstruction")
	}
}
