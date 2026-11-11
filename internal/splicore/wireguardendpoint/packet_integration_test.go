//go:build with_gvisor

package wireguardendpoint

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestWireGuardPacketCancellation(t *testing.T) {
	for _, mode := range []string{"close", "preset", "after-start", "endpoint"} {
		t.Run(mode, func(t *testing.T) {
			a, _, _, _ := pair(t, false)
			entered := make(chan struct{})
			var active atomic.Int64
			a.options.LookupHost = func(ctx context.Context, _ string) ([]netip.Addr, error) {
				active.Add(1)
				defer active.Add(-1)
				close(entered)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			conn, err := a.ListenPacket(context.Background(), access.Endpoint{Host: "10.34.0.2", Port: 12346})
			if err != nil {
				t.Fatal(err)
			}
			p := conn.(*routedPacket)
			defer p.Close()
			if mode == "preset" {
				if err = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			done := packetStart(p)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("Core DNS not entered")
			}
			start := time.Now()
			want := net.ErrClosed
			switch mode {
			case "close":
				err = p.Close()
			case "endpoint":
				err = a.Close()
			default:
				want = os.ErrDeadlineExceeded
				if mode == "after-start" {
					err = p.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if !errors.Is(err, want) {
					t.Fatalf("WriteTo error=%v want=%v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked WriteTo outlived Close/deadline")
			}
			if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
				t.Fatalf("cancellation took %s", elapsed)
			} else {
				t.Logf("%s cancellation=%s", mode, elapsed)
			}
			if active.Load() != 0 {
				t.Fatal("Core DNS operation leaked")
			}
			packetIdle(t, p, &packetDNS{})
		})
	}
}

func TestWireGuardPacketDomainAndLiteral(t *testing.T) {
	a, _, _, _ := pair(t, false)
	var queries atomic.Int64
	a.options.LookupHost = func(context.Context, string) ([]netip.Addr, error) {
		queries.Add(1)
		return []netip.Addr{netip.MustParseAddr("10.34.0.2")}, nil
	}
	for _, host := range []string{"10.34.0.2", "target.invalid"} {
		t.Run(host, func(t *testing.T) {
			conn, err := a.ListenPacket(context.Background(), access.Endpoint{Host: "10.34.0.2", Port: 12346})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			payload := []byte("Core DNS WireGuard UDP")
			if n, err := conn.WriteTo(payload, packetAddress(net.JoinHostPort(host, "12346"))); err != nil || n != len(payload) {
				t.Fatalf("WriteTo n=%d err=%v", n, err)
			}
			b := make([]byte, 128)
			n, source, err := conn.ReadFrom(b)
			if err != nil || !bytes.Equal(b[:n], payload) || source.String() != "10.34.0.2:12346" {
				t.Fatalf("WireGuard echo n=%d source=%v err=%v", n, source, err)
			}
			if host == "10.34.0.2" && queries.Load() != 0 {
				t.Fatal("IP literal invoked DNS")
			}
		})
	}
	if queries.Load() != 1 {
		t.Fatalf("Core DNS calls=%d want=1", queries.Load())
	}
}
