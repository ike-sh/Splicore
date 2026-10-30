//go:build linux && with_gvisor

package amneziawgendpoint

import (
	"context"
	"net"
	"os"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

// This gate requires a compatible, already loaded AWG 3.1 module. Neither the
// test nor production code installs or loads one. Absence is NOT qualification.
func TestPhase37AWGKernelQualification(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE37_KERNEL") != "1" {
		t.Skip("NOT QUALIFIED — COMPATIBLE AWG 3.1 KERNEL MODULE HOST UNAVAILABLE")
	}
	if err := loadedModule(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Run("official-userspace-interop", func(t *testing.T) { testOfficialAWG31Profiles(t, E.AWGKernel) })
	for _, clientBackend := range []E.AmneziaWGBackend{E.AWGUserspace, E.AWGKernel} {
		t.Run("client-"+string(clientBackend), func(t *testing.T) {
			for range 100 {
				ck, cp := testKeys(t)
				sk, sp := testKeys(t)
				client, server := qualificationProfile("I"), qualificationProfile("I")
				client.Backend, server.Backend = clientBackend, E.AWGKernel
				client.Tag, client.PrivateKey, client.Addresses = "kernel-client", ck, []string{"10.36.0.1/32", "fd36::1/128"}
				server.Tag, server.PrivateKey, server.Addresses = "kernel-server", sk, []string{"10.36.0.2/32", "fd36::2/128"}
				server.Peers = []E.WireGuardPeer{{PublicKey: cp, AllowedIPs: client.Addresses}}
				peer := performanceEndpoint(t, server)
				client.Peers = []E.WireGuardPeer{{PublicKey: sp, AllowedIPs: server.Addresses, Endpoint: net.JoinHostPort("127.0.0.1", itoa(peer.Status().ListenPort))}}
				e := performanceEndpoint(t, client)
				for _, ip := range []string{"10.36.0.2", "fd36::2"} {
					transferTCP(t, e, ip)
					transferUDP(t, e, ip, 1024)
				}
				for _, ip := range []string{"10.36.0.1", "fd36::1"} {
					transferTCP(t, peer, ip)
					transferUDP(t, peer, ip, 1024)
				}
				closedStatus(t, e)
				closedStatus(t, peer)
			}
		})
	}
}
