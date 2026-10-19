//go:build linux && with_quic

package session

import (
	"fmt"
	"testing"
)

func TestOfficialClientSendHalfLifecycle(t *testing.T) {
	root := oracleRoot(t)
	for _, mode := range []string{"http3", "http2"} {
		t.Run(mode, func(t *testing.T) {
			_, h2, h3, tc := startOfficialEndpoint(t, root, false)
			address := h3
			if mode == "http2" {
				address = h2
			}
			c := newClient(t, mode, address, tc, nil)
			for _, size := range []int{1, 2, 1024, 16383, 16384, 16385} {
				t.Run(fmt.Sprint(size), func(t *testing.T) { halfCloseExchange(t, c, size, nil) })
			}
		})
	}
}
