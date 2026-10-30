package device

import (
	"crypto/rand"
	"strconv"
	"unicode"
)

const digits10 = "0123456789"

func newRandDigitsObf(val string) (obf, error) {
	length, err := strconv.Atoi(val)
	if err != nil {
		return nil, err
	}

	return &randDigitObf{
		length: length,
	}, nil
}

type randDigitObf struct {
	length int
	random func([]byte) (int, error)
}

func (o *randDigitObf) Obfuscate(dst, src []byte) {
	random := o.random
	if random == nil {
		random = rand.Read
	}
	random(dst[:o.length])
	for i := range dst[:o.length] {
		dst[i] = digits10[dst[i]%10]
	}
}

func (o *randDigitObf) Deobfuscate(dst, src []byte) bool {
	for _, b := range src[:o.length] {
		if !unicode.IsDigit(rune(b)) {
			return false
		}
	}
	return true
}

func (o *randDigitObf) ObfuscatedLen(n int) int {
	return o.length
}

func (o *randDigitObf) DeobfuscatedLen(n int) int {
	return 0
}
