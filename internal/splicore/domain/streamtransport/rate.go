package streamtransport

import (
	"math"
	"strconv"
	"strings"
)

// RateBytes accepts integer decimal bit rates. Wire/controller rates are bytes
// per second; division by eight rounds down explicitly. Nonzero rates must
// provide at least 65536 bytes/s. The upper bound is one terabit/s.
func RateBytes(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, bad()
	}
	n, e := strconv.ParseUint(s[:i], 10, 64)
	if e != nil {
		return 0, bad()
	}
	m := uint64(1)
	switch strings.TrimSpace(s[i:]) {
	case "", "bps":
	case "k", "kbps":
		m = 1000
	case "m", "mbps":
		m = 1000000
	case "g", "gbps":
		m = 1000000000
	case "t", "tbps":
		m = 1000000000000
	default:
		return 0, bad()
	}
	if n > math.MaxUint64/m {
		return 0, bad()
	}
	bits := n * m
	if bits > 1000000000000 || bits != 0 && bits < 65536*8 {
		return 0, bad()
	}
	return bits / 8, nil
}
