package wire

import (
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/blake2b"
)

// The v6 wire constants and label assignments were researched against the
// GPL-3.0 sing-snell reference (SagerNet contributors). This implementation
// represents them as an immutable recipe, shared only by record directions.
// See the external SNELL_WIRE_SPEC_NOTES.md and differential evidence.
const gamma uint64 = 0x9e3779b97f4a7c15

type recipe struct {
	ns                      [7]uint64 // profile, prefix, motif, salt, mix, chunk, write
	v                       [40]int
	g                       [6]int
	buckets                 [3][8]int // chunks, subsequent writes, initial writes
	saltSize                int
	saltPositions           [16]int
	saltMasks               [16]byte
	firstCap, jitterPercent int
}

func scramble(x uint64) uint64 {
	x = (x ^ x>>30) * 0xbf58476d1ce4e5b9
	x = (x ^ x>>27) * 0x94d049bb133111eb
	return x ^ x>>31
}
func folded(x uint64) uint32 { y := scramble(x); return uint32(y ^ y>>32) }
func sample(ns uint64, label, a, b uint32) uint32 {
	return folded(ns ^ (uint64(b)*0x589965cc75374cc3 + 0x33a213ec50ffe2e9) ^
		uint64(label)*gamma ^ (uint64(a)*0xe7037ed1a0b428db + 0x8f3907f7b2b80c35))
}
func namespaceFor(label uint32) int {
	switch label {
	case 0, 1, 14, 15, 33, 34:
		return 1
	case 2:
		return 2
	case 3, 16, 17, 18, 19, 20:
		return 4
	case 21, 22, 23, 24, 25, 26, 38, 39:
		return 5
	case 28, 29, 30, 31, 32, 35, 36, 37:
		return 6
	default:
		return 0
	}
}
func bounded(raw uint32, low, high int) int { return low + int(uint64(raw)%uint64(high-low+1)) }
func (r *recipe) prf(label, a, b uint32) uint32 {
	return sample(r.ns[namespaceFor(label)], label, a, b)
}
func (r *recipe) rangeAt(label, a, b uint32, low, high int) int {
	return bounded(r.prf(label, a, b), low, high)
}

func makeRecipe(psk []byte) *recipe {
	seed := []byte{0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac}
	secret := blake2b.Sum256(append(seed, psk...))
	base := binary.LittleEndian.Uint64(secret[:8]) ^ (binary.LittleEndian.Uint64(secret[8:16]) + gamma) ^
		bits.RotateLeft64(binary.LittleEndian.Uint64(secret[16:24]), 17) ^ bits.RotateLeft64(binary.LittleEndian.Uint64(secret[24:]), -11)
	r := &recipe{}
	for i, item := range [...]struct{ label, seed uint64 }{{5, 0xb46c2e7d9a1538f1}, {0, 0x5d9217c083e64ab9}, {2, 0xa71f0c54d8396e2b}, {3, 0x3e8a91b52740f6cd}, {16, 0xc9f4260b7d1e835a}, {21, 0x62d0b5e19c4a783f}, {28, 0x917b3c48e6a205d4}} {
		r.ns[i] = scramble(base ^ item.label*0xd6e8feb86659fd93 ^ (item.seed + 0xa0761d6478bd642f))
	}
	for _, item := range [...]struct {
		label     uint32
		low, high int
	}{
		{6, 0, 3}, {7, 24, 160}, {8, 160, 960}, {9, 2, 8}, {10, 2, 11}, {11, 96, 768}, {12, 24, 41}, {13, 58, 76},
		{14, 8, 80}, {15, 16, 160}, {16, 0, 2}, {17, 1, 3}, {18, 2, 13}, {19, 0, 15}, {20, 8, 64},
		{21, 0, 2}, {22, 512, 1460}, {23, 8192, 16383}, {24, 1024, 4096}, {25, 16, 192}, {27, 12, 90},
		{28, 0, 2}, {29, 4, 8}, {32, 8, 96},
	} {
		r.v[item.label] = r.rangeAt(item.label, 0, 0, item.low, item.high)
	}
	r.v[8] = min(r.v[7]+r.v[8], 730)
	r.v[15] = min(r.v[14]+r.v[15], 128)
	r.v[24] = min(r.v[24], 2920)
	r.v[25] = min(r.v[25], 182)
	r.firstCap = min(r.rangeAt(22, 0, 0xf17c, 256, 768), min(r.v[22], 768))
	r.jitterPercent = r.rangeAt(28, 0, 0x504c, 8, 48)
	for i, limits := range [6][2]int{{24, 128}, {16, 96}, {16, 96}, {0, 9}, {1, 8}, {7, 23}} {
		r.g[i] = r.rangeAt(6, 0, uint32(i+1), limits[0], limits[1])
	}
	for i := range 8 {
		r.buckets[0][i] = r.rangeAt(26, 0, uint32(i), 4096, r.v[23])
		r.buckets[1][i] = r.rangeAt(30, 0, uint32(i), 320, 1460)
		r.buckets[2][i] = r.rangeAt(31, 0, uint32(i), 360, 1460)
	}
	lo := r.rangeAt(14, 0, 0x7053, 16, 96)
	hi := min(lo+r.rangeAt(15, 0, 0x7053, 16, 160), 128)
	r.saltSize = 16 + r.rangeAt(33, 0, 0x7053, lo, hi)
	perm := make([]int, r.saltSize)
	for i := range perm {
		perm[i] = i
	}
	for round := range r.rangeAt(17, 0, 0x51a7, 1, 4) {
		for i := range perm {
			raw := folded(r.ns[3] ^ 0xdaa66d2c7ddf743f ^ (uint64(i)*0x589965cc75374cc3 + 0x33a213ec50ffe2e9) ^ (uint64(0x51a7+round)*0xe7037ed1a0b428db + 0x8f3907f7b2b80c35))
			j := i + int(uint64(raw)%uint64(len(perm)-i))
			perm[i], perm[j] = perm[j], perm[i]
		}
	}
	stride := byte(r.rangeAt(18, 0, 0x51a7, 17, 251))
	for i := range 16 {
		r.saltPositions[i] = perm[i]
		r.saltMasks[i] = byte(i)*stride ^ byte(sample(r.ns[3], 2, 0x51a7, uint32(i)))
	}
	return r
}

func (r *recipe) expand(label, seq uint32, p []byte) {
	x := r.ns[namespaceFor(label)] ^ (uint64(seq)*0xd6e8feb86659fd93 + 0xb57de1f3f82cb33f) ^
		uint64(label)*0xa24baed4963ee407 ^ (uint64(len(p))*0x165667b19e3779f9 + 0x0d4cd3e7b14a36d7)
	for offset := 0; offset < len(p); offset += 8 {
		x += gamma
		word := scramble(x)
		for j := 0; j < min(8, len(p)-offset); j++ {
			p[offset+j] = byte(word >> uint(8*j))
		}
	}
}

// Normative wire data: patterns with each possible bit density, selected by
// the low nibble before the per-byte rotation. This is not a crypto primitive.
var densityPatterns = [8][16]byte{
	{},
	{1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128},
	{3, 5, 9, 17, 33, 65, 129, 6, 10, 18, 34, 66, 130, 12, 24, 36},
	{7, 11, 19, 35, 67, 131, 13, 25, 49, 97, 193, 14, 28, 56, 112, 224},
	{15, 23, 39, 71, 135, 27, 51, 99, 195, 29, 57, 113, 225, 60, 120, 240},
	{248, 244, 236, 220, 188, 124, 242, 230, 206, 158, 62, 241, 227, 199, 143, 31},
	{252, 250, 246, 238, 222, 190, 126, 249, 245, 237, 221, 189, 125, 243, 231, 219},
	{254, 253, 251, 247, 239, 223, 191, 127, 254, 253, 251, 247, 239, 223, 191, 127},
}

func (r *recipe) fill(seq uint32, p []byte) {
	r.expand(0, seq, p)
	var motif [32]byte
	if r.v[6] == 3 {
		r.expand(2, seq, motif[:])
	}
	density := max(1, min(7, (8*r.rangeAt(1, seq, 0, r.v[12], r.v[13])+50)/100))
	for i, value := range p {
		switch r.v[6] {
		case 0:
			mix := byte(int(value) + i)
			p[i] = bits.RotateLeft8(densityPatterns[density][(mix^value)&15], int((mix^(value>>4))&7))
		case 1:
			bucket := int(value) % (r.g[0] + r.g[1] + r.g[2])
			if bucket < r.g[0] {
				p[i] = byte(32 + int(byte(int(value)+i))%95)
			} else if bucket < r.g[0]+r.g[1] {
				p[i] = byte(128 + int(byte(int(value)^i))%64)
			} else {
				p[i] = byte(192 + int(byte(int(value)+i*7))%64)
			}
		case 2:
			p[i] = byte((int(value)+((i&3)<<4)+48)&240 | ((int(value&15) + r.g[3] + (i & 1)) % 10))
		case 3:
			phase := i % r.g[5]
			if phase < r.g[5]-3 {
				p[i] = byte((r.g[4]+3)*i) ^ motif[i%(r.g[4]*4)]
			} else if phase < r.g[5]-1 {
				p[i] = 48 | value%10
			}
		}
	}
}

func (r *recipe) swap(seq uint32, pad, body []byte) {
	n := min(len(pad), len(body))
	for round := range r.v[17] {
		for i := range n {
			stride := r.v[18] + round%3
			selected := false
			switch r.v[16] {
			case 0:
				selected = i%stride == r.v[19]%stride
			case 1:
				selected = i/r.v[20]%2 == round%2 && i/r.v[20]*r.v[20]+r.v[20] <= n
			case 2:
				selected = i%stride == int((uint64(r.prf(3, seq, uint32(round)))+uint64(r.v[19]))%uint64(stride))
			}
			if selected {
				pad[i], body[i] = body[i], pad[i]
			}
		}
	}
}

func (r *recipe) layout(seq uint32, payload int, first bool) (prefix, padding int) {
	prefix = r.rangeAt(33, seq, 0, r.v[14], r.v[15])
	if int(seq) < r.v[9] || payload > 0 && payload <= r.v[11] || seq%uint32(r.v[10]) == 0 {
		padding = r.rangeAt(34, seq, uint32(payload), r.v[7], r.v[8])
	}
	salt := 0
	if first {
		salt = r.saltSize
	}
	frame := salt + prefix + 23 + padding + payload
	if payload > 0 {
		frame += 16
	}
	target := min(frame, 65535)
	if frame <= 1459 {
		if int(seq) < r.v[29] {
			target = r.buckets[2][seq]
		} else {
			target = r.buckets[1][r.prf(35, seq, uint32(frame))%8]
		}
		if r.v[28] == 2 {
			target = max(1, target+r.rangeAt(36, seq, 0, -r.v[32], r.v[32]))
		}
		spread := min(730, frame*r.jitterPercent/100)
		if r.prf(35, seq, uint32(spread))&1 == 0 {
			target = min(65535, target+spread)
		} else if target > spread/2 {
			target -= spread / 2
		}
		for target < frame {
			next := r.buckets[1][r.prf(37, seq, uint32(target))%8]
			if next <= target {
				next = target + r.v[8]
			}
			target = min(next, 65535)
		}
	}
	padding += max(0, min(target-frame, 730))
	if first {
		overhead := 55
		if payload == 0 {
			overhead = 39
		}
		threshold := max(((payload+overhead)*25+74)/75, 192)
		padding = max(padding, min(threshold-(salt-16)-prefix, r.v[8]+730))
	}
	return prefix, min(padding, 65535)
}
