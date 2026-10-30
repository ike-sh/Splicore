package device

import "crypto/rand"

// These private hooks are set only on unstarted devices in package tests.
// They cover shaping bytes, H/CPA/timing choices, jitter and junk lengths.
// Cryptographic keys, Noise ephemeral keys and cookie secrets remain untouched.
func (d *Device) obfuscationUintn(n uint32) uint32 {
	if n == 0 {
		return 0
	}
	if draw := d.obfuscationRNG.uintn; draw != nil {
		return draw(n)
	}
	return fastrandn(n)
}

func (d *Device) obfuscationBytes(b []byte) (int, error) {
	if fill := d.obfuscationRNG.bytes; fill != nil {
		return fill(b)
	}
	return rand.Read(b)
}

func (d *Device) pickRange(r UintRange) uint32 { return r.pickOne(d.obfuscationUintn) }
