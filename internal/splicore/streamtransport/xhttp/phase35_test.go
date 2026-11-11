//go:build with_quic

package xhttp

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type initialCapture struct {
	net.PacketConn
	mu      sync.Mutex
	initial []byte
}

func (p *initialCapture) WriteTo(b []byte, a net.Addr) (int, error) {
	p.mu.Lock()
	if p.initial == nil && len(b) > 5 && b[0]&0xc0 == 0xc0 {
		p.initial = bytes.Clone(b)
	}
	p.mu.Unlock()
	return p.PacketConn.WriteTo(b, a)
}

func TestPhase35H3Profiles(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(map[bool]string{false: "ChromeParrot", true: "StandardTLS"}[plain], func(t *testing.T) {
			cl, _, _ := h3Fixture(t, cfg.Config{Kind: "xhttp", H3: &cfg.H3{DisableChromeParrot: plain, InitialStreamWindow: 1 << 20, MaxStreamWindow: 8 << 20, InitialConnectionWindow: 4 << 20, MaxConnectionWindow: 32 << 20, MaxIdleTimeout: 30, KeepAlivePeriod: 2, MaxIncomingStreams: 64, DisableGSO: true}})
			original := cl.security.PacketSocket
			var captured *initialCapture
			cl.security.PacketSocket = func(ctx context.Context) (net.PacketConn, net.Addr, error) {
				p, a, err := original(ctx)
				if err != nil {
					return p, a, err
				}
				captured = &initialCapture{PacketConn: p}
				return captured, a, nil
			}
			c, err := cl.DialContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			exchange(t, c, bytes.Repeat([]byte("profile"), 50000))
			captured.mu.Lock()
			initial := bytes.Clone(captured.initial)
			captured.mu.Unlock()
			// The client's source CID follows its (nonempty) destination CID.
			scidOffset := 6 + int(initial[5])
			if len(initial) < 1200 || scidOffset >= len(initial) || (!plain && initial[scidOffset] != 0) || (plain && initial[scidOffset] == 0) {
				t.Fatal("client QUIC CID profile", len(initial))
			}
			cl.pool.mu.Lock()
			defer cl.pool.mu.Unlock()
			for _, entry := range cl.pool.entries {
				h := entry.transport.(*h3Transport)
				h.mu.Lock()
				for s := range h.sockets {
					if s.conn != nil && (s.conn.ConnectionState().TLS.DidResume || s.conn.ConnectionState().Used0RTT) {
						t.Error("hidden resumption or early data")
					}
				}
				h.mu.Unlock()
			}
		})
	}
}
