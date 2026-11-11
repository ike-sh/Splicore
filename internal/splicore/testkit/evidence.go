package testkit

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// EvidenceName keeps IPv6 and subtest names valid on Windows as well as POSIX.
// The digest prevents different original names mapping to the same directory.
func EvidenceName(name string) string {
	clean := strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`<>:"/\|?*`, r) {
			return '_'
		}
		return r
	}, name)
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%s-%x", clean, sum[:4])
}
