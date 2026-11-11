//go:build linux

package packet

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

// Invoked explicitly inside a new user+network namespace with loopback up.
// No test in the normal suite changes the host firewall.
func TestNFTRangeIsolatedKernelLifecycle(t *testing.T) {
	if os.Getenv("SPLICORE_NFT_ISOLATED_NAMESPACE") != "1" {
		t.Skip("explicit isolated network namespace required")
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			p, e := net.ListenPacket("udp", net.JoinHostPort(host, "65534"))
			if e != nil {
				t.Fatal(e)
			}
			packet, e := ServerRange(p, &cfg.HysteriaUDP{ServerPortRange: "65534-65535"})
			if e != nil {
				p.Close()
				t.Fatal(e)
			}
			packet.SetDeadline(time.Now().Add(3 * time.Second))
			client, e := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
			if e != nil {
				packet.Close()
				t.Fatal(e)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			dst := &net.UDPAddr{IP: net.ParseIP(host), Port: 65535}
			if _, e = client.WriteTo([]byte("range65535"), dst); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 128)
			n, a, e := packet.ReadFrom(b)
			if e != nil || string(b[:n]) != "range65535" {
				t.Fatal("kernel redirect", n, e)
			}
			if _, e = packet.WriteTo(b[:n], a); e != nil {
				t.Fatal(e)
			}
			n, from, e := client.ReadFrom(b)
			if e != nil || string(b[:n]) != "range65535" || from.(*net.UDPAddr).Port != 65535 {
				t.Fatal("reverse NAT", n, from, e)
			}
			if e = packet.Close(); e != nil {
				t.Fatal("owned cleanup", e)
			}
			packet.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			out, e := exec.CommandContext(ctx, "nft", "list", "tables").Output()
			if e != nil || strings.Contains(string(out), "splicore_hy2_") {
				t.Fatal("owned table leaked", e, string(out))
			}
		})
	}
}
