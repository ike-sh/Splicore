//go:build with_gvisor

package wireguardendpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
)

func TestXrayWireGuardPeerRejectsOccupiedPort(t *testing.T) {
	if os.Getenv("SPLICORE_PHASE34_XRAY_REFERENCE") == "" {
		t.Skip("external Xray WireGuard oracle not configured")
	}
	portRange, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	var low, high int
	if _, err := fmt.Sscan(string(portRange), &low, &high); err != nil {
		t.Fatal(err)
	}
	t.Logf("xray_port_environment namespace=%s range=%d-%d old_port_33434_in_range=%t",
		namespace, low, high, low <= 33434 && 33434 <= high)

	lease := testkit.ReserveDualPeerPort(t, "127.0.0.1")
	t.Cleanup(func() { checkXrayPeerReleased(t, lease.Address(), []string{"udp"}) })
	private, _ := testKeys(t)
	_, public := testKeys(t)
	config := xrayWireGuardServerConfig(t, lease.Port, E.EncodeKey(private.Reveal()), public, "")
	// Freeze this address as the old fixture would. A controlled socket
	// owner takes it after the parent's handoff and before Xray starts.
	// The chosen address comes from the OS, so the probe needs no fixed port.
	_, logPath, err := startXrayPeer(t, config, lease.Address(), func() {
		lease.ReleaseSockets()
		occupier, err := net.ListenPacket("udp4", lease.Address())
		if err != nil {
			t.Fatal("controlled UDP occupation", err)
		}
		t.Cleanup(func() { _ = occupier.Close() })
		if err := testkit.VerifyPeerProcessSockets(t, context.Background(), os.Getpid(), lease.Address(), "udp"); err != nil {
			t.Fatal("verify controlled occupier", err)
		}
	}, "udp")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 255 {
		t.Fatalf("expected Xray bind failure before fixture readiness, got %v", err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	bindFailure := "listen udp " + lease.Address() + ": bind: address already in use"
	if !strings.Contains(string(raw), bindFailure) {
		t.Fatal("Xray exit did not identify the occupied UDP listener")
	}
	t.Logf("xray_occupied_port_rejected pid=%d address=%s exit=255 error=%s",
		exit.ProcessState.Pid(), lease.Address(), bindFailure)
}
