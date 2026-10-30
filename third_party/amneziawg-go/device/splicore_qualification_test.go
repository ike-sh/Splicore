package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

func TestSplicoreTimerResetExpiryRace(t *testing.T) {
	var peer Peer
	var fired atomic.Int64
	timer := peer.NewTimer(func(*Peer, time.Duration) { fired.Add(1) })
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 10000 {
				timer.Mod(time.Nanosecond)
				_ = timer.IsPending()
			}
		})
	}
	wg.Wait()
	timer.DelSync()
	before := fired.Load()
	time.Sleep(time.Millisecond)
	if timer.IsPending() || fired.Load() != before {
		t.Fatal("timer survived DelSync")
	}
	timer.Mod(time.Millisecond)
	until := time.Now().Add(time.Second)
	for fired.Load() == before && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	timer.DelSync()
	if fired.Load() == before {
		t.Fatal("reset lost")
	}
}

// Hold the first reader after it has captured S4, then configure a different
// S4. The first payload must arrive; a second packet cannot hide the defect.
type gatedTUN struct {
	tun.Device
	entered, release chan struct{}
	once             sync.Once
}

func (g *gatedTUN) Read(b [][]byte, s []int, o int) (int, error) {
	g.once.Do(func() { close(g.entered); <-g.release })
	return g.Device.Read(b, s, o)
}
func TestSplicoreFirstS4Packet(t *testing.T) {
	cfgs, endpoints := genConfigs(t, "s1", "12", "s2", "13", "s3", "14", "s4", "29", "header_protection_key", "2525252525252525252525252525252525252525252525252525252525252525")
	var pair testPair
	for i := range pair {
		p := &pair[i]
		p.tun = tuntest.NewChannelTUN()
		p.ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
		gate := &gatedTUN{Device: p.tun.TUN(), entered: make(chan struct{}), release: make(chan struct{})}
		p.dev = NewDevice(gate, conn.NewDefaultBind(), &Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}})
		<-gate.entered
		err := p.dev.IpcSet(cfgs[i])
		close(gate.release)
		t.Cleanup(p.dev.Close)
		if err != nil {
			t.Fatal("configuration rejected")
		}
		if err = p.dev.Up(); err != nil {
			t.Fatal(err)
		}
	}
	for i := range pair {
		if err := pair[i].dev.IpcSet(fmt.Sprintf(endpoints[i], pair[i^1].dev.net.port)); err != nil {
			t.Fatal(err)
		}
	}
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}
func TestSplicoreClassifierHPKAllTypes(t *testing.T) {
	var d Device
	for i, r := range []*AtomicUintRange{&d.headers.init, &d.headers.response, &d.headers.cookie, &d.headers.transport} {
		var v UintRange
		v.FromUint32(uint32(101+i*100), uint32(109+i*100))
		r.Store(v)
	}
	d.paddings.init.Store(12)
	d.paddings.response.Store(13)
	d.paddings.cookie.Store(14)
	d.paddings.transport.Store(15)
	for i := range d.headerProtection.key {
		d.headerProtection.key[i] = byte(i + 1)
	}
	sizes := []int{MessageInitiationSize, MessageResponseSize, MessageCookieReplySize, MessageTransportSize + 40}
	for i, size := range sizes {
		prefix := 12 + i
		plain := make([]byte, size)
		binary.LittleEndian.PutUint32(plain, uint32(105+i*100))
		for j := 4; j < len(plain); j++ {
			plain[j] = byte(j)
		}
		packet := make([]byte, prefix+size)
		for j := range prefix {
			packet[j] = byte(j + 11)
		}
		copy(packet[prefix:], plain)
		cipher, e := d.HeaderProtectionCipher(packet[:12])
		if e != nil {
			t.Fatal(e)
		}
		protected := size
		if i == 3 {
			protected = 16
		}
		cipher.XORKeyStream(packet[prefix:prefix+protected], packet[prefix:prefix+protected])
		if bytes.Equal(packet[prefix:prefix+4], plain[:4]) {
			t.Fatal("unprotected header")
		}
		cipher, _ = d.HeaderProtectionCipher(packet[:12])
		hash := make([]byte, 4)
		cipher.XORKeyStream(hash, hash)
		_, typ, pad := d.DeterminePacketTypeAndPadding(packet, hash)
		if typ != uint32(i+1) || pad != uint32(prefix) {
			t.Fatal("wrong protected message type")
		}
		applyHash(packet[prefix:prefix+4], packet[prefix:prefix+4], hash)
		cipher.XORKeyStream(packet[prefix+4:prefix+protected], packet[prefix+4:prefix+protected])
		if !bytes.Equal(packet[prefix:], plain) {
			t.Fatal("HPK protected incorrect portion")
		}
	}
}
func TestSplicorePaddingWindowAndPrecedence(t *testing.T) {
	var d Device
	p := &Peer{device: &d}
	var r UintRange
	r.FromUint32(20, 40)
	d.contentPaddingAddition.Store(r)
	for _, window := range []uint32{0, 500, 1500, 65507} {
		p.udpWindow.Store(window)
		for _, size := range []int{0, 32, 499, 500, 501, 1420, 1500, 65507} {
			for range 100 {
				n := p.randomPaddingAddition(size)
				if n < 0 || n > 40 || size <= int(window) && n > int(window)-size || size > int(window) && n != 0 {
					t.Fatal("padding escaped UDP window")
				}
			}
		}
	}
	for _, mtu := range []int{1280, 1420, 9000} {
		for _, size := range []int{0, 1, mtu - 1, mtu, mtu + 1, 65500} {
			n := calculatePaddingSize(size, mtu)
			if n < 0 || n > 15 {
				t.Fatal("padding wraparound")
			}
		}
	}
	d.contentPaddingAddition.Store(0)
	if p.randomPaddingAddition(64) != -1 || p.randomTrailer(64) != -1 {
		t.Fatal("disabled precedence")
	}
}
func TestSplicoreCPSJunkAndTimings(t *testing.T) {
	chain, e := newObfChain("<b 0102><t><r 0><rc 20><rd 20><dz 2><d><ds>")
	if e != nil {
		t.Fatal(e)
	}
	packet := make([]byte, chain.ObfuscatedLen(0))
	before := uint32(time.Now().Unix())
	chain.Obfuscate(packet, nil)
	after := uint32(time.Now().Unix())
	stamp := binary.BigEndian.Uint32(packet[2:6])
	if stamp < before || stamp > after || !bytes.Equal(packet[:2], []byte{1, 2}) {
		t.Fatal("CPS binary/timestamp vector")
	}
	for _, b := range packet[6:26] {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z') {
			t.Fatal("rc alphabet")
		}
	}
	for _, b := range packet[26:46] {
		if b < '0' || b > '9' {
			t.Fatal("rd alphabet")
		}
	}
	var d Device
	d.junk.count.Store(8)
	d.junk.min.Store(20)
	d.junk.max.Store(40)
	for range 100 {
		packets := d.JunkPackets()
		if len(packets) != 8 {
			t.Fatal("junk count")
		}
		for _, b := range packets {
			if len(b) < 20 || len(b) >= 40 {
				t.Fatal("junk exclusive max")
			}
		}
	}
	var r UintRange
	r.FromUint32(2, 4)
	d.timings.rekeyTimeoutSec.Store(r)
	d.timings.keepaliveTimeoutSec.Store(r)
	p := &Peer{device: &d}
	for range 1000 {
		v := p.retransmitHandshakeTimeout()
		if v < 2*time.Second || v > 4*time.Second {
			t.Fatal("timing bounds")
		}
	}
	r.FromUint32(3, 3)
	d.timings.rekeyTimeoutSec.Store(r)
	if p.retransmitHandshakeTimeout() != 3*time.Second {
		t.Fatal("fixed timing units")
	}
}
func TestSplicoreDisableCookiesUnderLoad(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		pair := genTestPair(t, true, "s1", "12", "s2", "13", "s3", "14", "s4", "15", "header_protection_key", "2525252525252525252525252525252525252525252525252525252525252525")
		for _, p := range pair {
			p.dev.disableCookies.Store(disabled)
			p.dev.rate.underLoadUntil.Store(time.Now().Add(time.Second).UnixNano())
			if !p.dev.IsUnderLoad() {
				t.Fatal("underload not forced")
			}
		}
		pair.Send(t, Ping, nil)
		pair.Send(t, Pong, nil)
	}
}
func FuzzSplicoreClassifierAndHPK(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0}, uint16(12))
	f.Fuzz(func(t *testing.T, b []byte, s uint16) {
		if len(b) > 65535 {
			return
		}
		var d Device
		var r UintRange
		r.FromUint32(1, 1)
		d.headers.init.Store(r)
		d.paddings.init.Store(uint32(s))
		size, _, p := d.DeterminePacketTypeAndPadding(b, []byte{0, 0, 0, 0})
		if int(p)+size > len(b) {
			t.Fatal("classifier out of bounds")
		}
	})
}

func TestSplicoreDeterministicRandomAndTimestamp(t *testing.T) {
	var r UintRange
	r.FromUint32(9, 17)
	if r.pickOne(func(n uint32) uint32 {
		if n != 9 {
			t.Fatal("range width")
		}
		return 0
	}) != 9 || r.pickOne(func(n uint32) uint32 { return n - 1 }) != 17 {
		t.Fatal("inclusive selection edges")
	}
	b := make([]byte, 4)
	o := timestampObf{now: func() time.Time { return time.Unix(0x12345678, 0) }}
	o.Obfuscate(b, nil)
	if !bytes.Equal(b, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Fatal("timestamp width/endian")
	}
	fill := func(b []byte) (int, error) {
		for i := range b {
			b[i] = byte(i)
		}
		return len(b), nil
	}
	raw := randObf{length: 4, random: fill}
	raw.Obfuscate(b, nil)
	if !bytes.Equal(b, []byte{0, 1, 2, 3}) {
		t.Fatal("random byte source")
	}
	chars := randCharObf{length: 4, random: fill}
	chars.Obfuscate(b, nil)
	if string(b) != "abcd" {
		t.Fatal("ASCII letter mapping")
	}
	digits := randDigitObf{length: 4, random: fill}
	digits.Obfuscate(b, nil)
	if string(b) != "0123" {
		t.Fatal("ASCII digit mapping")
	}
	for _, high := range []bool{false, true} {
		var d Device
		d.obfuscationRNG.uintn = func(n uint32) uint32 {
			if high {
				return n - 1
			}
			return 0
		}
		d.obfuscationRNG.bytes = fill
		d.junk.min.Store(20)
		d.junk.max.Store(40)
		d.junk.count.Store(3)
		for _, packet := range d.JunkPackets() {
			want := 20
			if high {
				want = 39
			}
			if len(packet) != want || packet[1] != 1 {
				t.Fatal("deterministic junk extent/bytes")
			}
		}
		d.contentPaddingAddition.Store(r)
		d.timings.rekeyTimeoutSec.Store(r)
		peer := &Peer{device: &d}
		peer.udpWindow.Store(1000)
		want := 9
		if high {
			want = 17
		}
		if d.pickRange(r) != uint32(want) || peer.randomPaddingAddition(32) != want || peer.retransmitHandshakeTimeout() != time.Duration(want)*time.Second {
			t.Fatal("deterministic header/padding/timing selection")
		}
		prefix := make([]byte, 12)
		_, _ = d.obfuscationBytes(prefix)
		if prefix[11] != 11 {
			t.Fatal("deterministic prefix bytes")
		}
	}
}

func FuzzSplicorePaddingAndFraming(f *testing.F) {
	f.Add(uint16(12), uint16(500), uint16(40), uint16(1420), []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, size, window, addition, mtu uint16, nonce []byte) {
		var d Device
		p := &Peer{device: &d}
		p.udpWindow.Store(uint32(window))
		var r UintRange
		r.FromUint32(uint32(addition), uint32(addition))
		d.contentPaddingAddition.Store(r)
		n := p.randomPaddingAddition(int(size))
		if n >= 0 && n > max(0, int(window)-int(size)) {
			t.Fatal("padding exceeded window")
		}
		padding := calculatePaddingSize(int(size), int(mtu))
		if padding < 0 || padding > 15 {
			t.Fatal("padding overflow")
		}
		d.headerProtection.key[0] = 1
		c, err := d.HeaderProtectionCipher(nonce)
		if err == nil {
			buf := make([]byte, 16)
			c.XORKeyStream(buf, buf)
		}
	})
}
func TestSplicoreIncomingCookieWithDisableCookies(t *testing.T) {
	pair := genTestPair(t, true, "s1", "12", "s2", "13", "s3", "14", "s4", "15", "header_protection_key", "2525252525252525252525252525252525252525252525252525252525252525", "rekey_timeout", "1")
	pair[0].dev.rate.underLoadUntil.Store(time.Now().Add(20 * time.Second).UnixNano())
	pair[1].dev.disableCookies.Store(true)
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
	// The initiator must have consumed the remote cookie despite its local
	// DisableCookies setting, otherwise under-load peer 0 cannot accept MAC2.
	for _, peer := range pair[1].dev.peers.keyMap {
		peer.cookieGenerator.RLock()
		valid := !peer.cookieGenerator.mac2.cookieSet.IsZero()
		peer.cookieGenerator.RUnlock()
		if !valid {
			t.Fatal("incoming cookie suppressed by DisableCookies")
		}
	}
}
