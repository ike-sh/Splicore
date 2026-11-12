package testkit

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

var portEnvironmentOnce sync.Once

// Read-only evidence, collected in the actual Windows test process. Historic
// ports are observations, never a fixed-port allocation policy or a pass gate.
func PeerPortEnvironment(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	portEnvironmentOnce.Do(func() {
		observations := map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH}
		for _, family := range []string{"ipv4", "ipv6"} {
			for _, kind := range []string{"tcp", "udp"} {
				for _, query := range []string{"dynamicport", "excludedportrange"} {
					args := []string{"interface", family, "show", query, "protocol=" + kind}
					out, err := exec.Command("netsh", args...).CombinedOutput()
					key := family + "/" + kind + "/" + query
					observations[key] = map[string]any{"command": append([]string{"netsh"}, args...), "output": string(out), "error": fmtPortError(err)}
					t.Logf("windows_port_environment query=%s error=%v output=\n%s", key, err, out)
				}
			}
		}
		for _, port := range []int{64187, 64194, 64201, 64208, 64215, 64222, 64234, 64241, 64248, 64255, 64262} {
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			tcp, te := net.Listen("tcp4", address)
			udp, ue := net.ListenPacket("udp4", address)
			var errno syscall.Errno
			_ = errors.As(ue, &errno)
			observations[address] = map[string]any{"tcp_error": fmtPortError(te), "udp_error": fmtPortError(ue), "udp_errno": uint64(errno)}
			t.Logf("windows_historical_port address=%s TCP=%v UDP=%v udp_errno=%d", address, te, ue, errno)
			if tcp != nil {
				_ = tcp.Close()
			}
			if udp != nil {
				_ = udp.Close()
			}
		}
		if root := os.Getenv("SPLICORE_PHASE33_PEER_LOGS"); root != "" {
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			data, err := json.MarshalIndent(observations, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "windows-port-environment-"+strconv.Itoa(os.Getpid())+".json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func fmtPortError(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// Windows netstat readback attributes both sockets to the actual child PID;
// a successful parent-side reservation or readiness marker alone is insufficient.
func VerifyDualPeerProcess(t *testing.T, pid int, address string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	out, err := exec.Command("netstat", "-ano").CombinedOutput()
	if err != nil {
		t.Fatal("child socket owner readback", err)
	}
	tcp, udp := false, false
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != address || fields[len(fields)-1] != strconv.Itoa(pid) {
			continue
		}
		if fields[0] == "TCP" && len(fields) == 5 && fields[3] == "LISTENING" {
			tcp = true
		}
		if fields[0] == "UDP" {
			udp = true
		}
		t.Logf("child_socket_owner pid=%d socket=%s", pid, strings.Join(fields, " "))
	}
	if !tcp || !udp {
		t.Fatalf("child pid=%d address=%s does not own required TCP/UDP listeners: tcp=%t udp=%t", pid, address, tcp, udp)
	}
}
