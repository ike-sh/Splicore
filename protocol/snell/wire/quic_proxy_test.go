package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func initialPacket(version uint32) []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	if version == 0x6b3343cf {
		p[0] = 0xd0
	}
	binary.BigEndian.PutUint32(p[1:], version)
	p[5] = 8
	copy(p[6:14], []byte("dest-cid"))
	p[14] = 8
	copy(p[15:23], []byte("src--cid"))
	p[23] = 0
	binary.BigEndian.PutUint16(p[24:], uint16(0x4000|1174))
	return p
}

func TestSnellQUICControlAndDetection(t *testing.T) {
	k, _ := NewKey(5, testPSK)
	wrong, _ := NewKey(5, "WrongSyntheticPassword")
	for _, version := range []uint32{1, 0x6b3343cf} {
		p := initialPacket(version)
		if !QUICInitial(p) {
			t.Fatal("valid Initial", version)
		}
		for _, host := range []string{"127.0.0.1", "::1", "sni-protected.synthetic.test"} {
			dst := access.Endpoint{Host: host, Port: 8443}
			packet, err := ProtectQUIC(k, dst, p)
			if err != nil {
				t.Fatal(err)
			}
			if QUICRaw(packet) || bytes.Contains(packet, []byte(host)) {
				t.Fatal("unprotected destination")
			}
			got, payload, err := UnprotectQUIC(k, packet)
			if err != nil || got != dst || !bytes.Equal(payload, p) {
				t.Fatal(got, err)
			}
			if _, _, err = UnprotectQUIC(wrong, packet); err == nil {
				t.Fatal("wrong PSK accepted")
			}
			for _, i := range []int{16, len(packet) - 1} {
				tampered := bytes.Clone(packet)
				tampered[i] ^= 1
				if _, _, err = UnprotectQUIC(k, tampered); err == nil {
					t.Fatal("tamper accepted")
				}
			}
			for i := range len(packet) {
				if _, _, err = UnprotectQUIC(k, packet[:i]); err == nil {
					t.Fatal("truncation accepted", i)
				}
			}
		}
	}
	for _, p := range [][]byte{nil, {0x40}, {0xc0}, {0xc0, 0, 0, 0, 1}, bytes.Repeat([]byte{0xff}, 1200), initialPacket(99)} {
		if QUICInitial(p) {
			t.Fatal("false positive")
		}
	}
	p := initialPacket(1)
	p[5] = 255
	if QUICInitial(p) {
		t.Fatal("malformed CID")
	}
}

func TestSnellV5OfficialDRSTransitions(t *testing.T) {
	k, _ := NewKey(5, testPSK)
	var out bytes.Buffer
	w := NewEncoder(&out, k)
	if err := w.initializeWriter(); err != nil {
		t.Fatal(err)
	}
	rd := NewDecoder(&out, k)
	first := 1460 - 55 - w.firstPadding
	for round := range 16 {
		want := bytes.Repeat([]byte{byte(round)}, 60000)
		if _, err := w.Write(want); err != nil {
			t.Fatal(err)
		}
		// The oracle grows once per submission, not per record or byte batch.
		limit := min(first+round*1421, 16383)
		var got []byte
		for len(got) < len(want) {
			chunk, err := rd.Next()
			if err != nil {
				t.Fatal(err)
			}
			if len(chunk) != min(limit, len(want)-len(got)) {
				t.Fatal("record limit", round, len(chunk), limit)
			}
			got = append(got, chunk...)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("record corruption")
		}
		if len(out.Bytes()) > len(want)+4096 {
			t.Fatal("unbounded record overhead")
		}
	}
	w.last = time.Now().Unix() - 31
	if got := w.limit(time.Now().Unix()); got != 1421 {
		t.Fatal("idle reset", got)
	}
}

func FuzzSnellQUICControl(f *testing.F) {
	f.Add([]byte{1, 0, 1, 'x', 0, 53, 0xc0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65507 {
			return
		}
		_, _, _ = decodeQUICControl(b)
		_ = QUICInitial(b)
	})
}
