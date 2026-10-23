//go:build with_quic && with_utls && !linux

package native

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
)

// /proc FD coverage is Linux-only. Keep the portable real lifecycle checks.
func sqResourceSubprocess(*testing.T) bool { return false }
func sqLifecycleTCP(t *testing.T) (net.Listener, func()) {
	return testfixture.TCP(t), func() {}
}
func sqResourceLifecycles(t *testing.T, _ net.Addr, _ func(), cycle func()) {
	before := runtime.NumGoroutine()
	for range 3 {
		cycle()
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if runtime.NumGoroutine() > before+8 {
		t.Fatal("goroutine growth", before, runtime.NumGoroutine())
	}
}
