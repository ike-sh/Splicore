//go:build with_utls

package native

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"testing"
)

// Readiness must belong to the real pinned child. An unrelated live listener
// cannot make a child that rejects its bind appear ready for protocol traffic.
func TestPhasePeerRejectsOccupiedListener(t *testing.T) {
	if os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE") == "" {
		t.Skip("pinned reference not configured")
	}
	if os.Getenv("SPLICORE_PHASE_PEER_COLLISION_CHILD") != "1" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.Command(exe, "-test.run=^TestPhasePeerRejectsOccupiedListener$", "-test.v", "-test.timeout=10s")
		child.Env = append(os.Environ(), "SPLICORE_PHASE_PEER_COLLISION_CHILD=1")
		output, err := child.CombinedOutput()
		if err == nil || !bytes.Contains(output, []byte("Xray rejected profile")) {
			t.Fatalf("readiness did not reject the occupied listener: %v\n%s", err, output)
		}
		t.Logf("pinned child bind rejection observed; unrelated TCP listener was not accepted as readiness")
		return
	}
	owner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	endpoint := netaddrEndpoint(owner.Addr())
	config := map[string]any{
		"log":       map[string]any{"loglevel": "debug"},
		"inbounds":  []any{map[string]any{"listen": endpoint.Host, "port": endpoint.Port, "protocol": "socks", "settings": map[string]any{"auth": "noauth"}}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	phasePeer(t, t.TempDir(), os.Getenv("SPLICORE_VLESS_ENCRYPTION_REFERENCE"), "collision", config, endpoint)
	t.Fatal("unrelated listener mistaken for pinned peer startup")
}
