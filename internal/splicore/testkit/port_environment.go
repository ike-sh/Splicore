package testkit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
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
		var errno syscall.Errno
		_ = errors.As(err, &errno)
		return fmt.Sprintf("%v [errno=%d]", err, errno)
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
	if err := VerifyPeerProcessSockets(t, context.Background(), pid, address, "tcp", "udp"); err != nil {
		t.Fatal(err)
	}
}

// VerifyPeerProcessSockets requires the exact bound endpoint and child PID for
// every requested protocol. Linux readback matches socket inodes to the child.
func VerifyPeerProcessSockets(t *testing.T, ctx context.Context, pid int, address string, networks ...string) error {
	t.Helper()
	var owned map[string]string
	var err error
	switch runtime.GOOS {
	case "linux":
		owned, err = linuxPeerSockets(pid, address, networks)
	case "windows":
		owned, err = windowsPeerSockets(ctx, pid, address)
	default:
		return fmt.Errorf("peer socket ownership readback unavailable on %s", runtime.GOOS)
	}
	if err != nil {
		return fmt.Errorf("child pid=%d socket owner readback: %w", pid, err)
	}
	for _, network := range networks {
		socket, found := owned[network]
		if !found {
			return fmt.Errorf("child pid=%d does not own %s listener at %s", pid, network, address)
		}
		t.Logf("child_socket_owner pid=%d socket=%s network=%s address=%s at=%s",
			pid, socket, network, address, time.Now().UTC().Format(time.RFC3339Nano))
	}
	return ctx.Err()
}

func windowsPeerSockets(ctx context.Context, pid int, address string) (map[string]string, error) {
	out, err := exec.CommandContext(ctx, "netstat", "-ano").CombinedOutput()
	if err != nil {
		return nil, err
	}
	owned := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[1] != address || fields[len(fields)-1] != strconv.Itoa(pid) {
			continue
		}
		if fields[0] == "UDP" || (fields[0] == "TCP" && len(fields) == 5 && fields[3] == "LISTENING") {
			owned[strings.ToLower(fields[0])] = strings.Join(fields, " ")
		}
	}
	return owned, nil
}

func linuxPeerSockets(pid int, address string, networks []string) (map[string]string, error) {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, err
	}
	if !endpoint.Addr().Is4() {
		return nil, fmt.Errorf("Linux peer socket readback requires an IPv4 endpoint: %s", address)
	}
	ip := endpoint.Addr().As4()
	local := fmt.Sprintf("%08X:%04X", binary.NativeEndian.Uint32(ip[:]), endpoint.Port())
	process := filepath.Join("/proc", strconv.Itoa(pid))
	fdDir := filepath.Join(process, "fd")
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, err
	}
	sockets := make(map[string]string)
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		sockets[link] = fd.Name()
	}
	namespace, err := os.Readlink(filepath.Join(process, "ns", "net"))
	if err != nil {
		return nil, err
	}
	owned := make(map[string]string)
	for _, network := range networks {
		var state string
		switch network {
		case "udp":
			state = "07" // Bound without a connected remote.
		case "tcp":
			state = "0A" // LISTEN.
		default:
			return nil, fmt.Errorf("unsupported peer protocol: %s", network)
		}
		table, err := os.ReadFile(filepath.Join(process, "net", network))
		if err != nil {
			return nil, err
		}
		// The table is namespace-wide. Its inode must also exist in this
		// process's fd directory before the socket can count as ready.
		for _, line := range strings.Split(string(table), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[1] != local || fields[3] != state {
				continue
			}
			if fd, found := sockets["socket:["+fields[9]+"]"]; found {
				owned[network] = fmt.Sprintf("fd=%s inode=%s namespace=%s", fd, fields[9], namespace)
				break
			}
		}
	}
	return owned, nil
}
