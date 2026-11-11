package wireguardendpoint

import (
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
)

// Exercise native Winsock on owned sockets. No adapter, route, firewall or
// network-profile mutation is needed to distinguish truncation from filtering.
func windowsNativeTargets(t *testing.T) map[string]string {
	t.Helper()
	targets := map[string]string{"loopback-ipv4": "127.0.0.1", "loopback-ipv6": "::1"}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil || !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
				continue
			}
			family := "nic-ipv6"
			if ip.To4() != nil {
				family = "nic-ipv4"
			}
			if targets[family] == "" {
				targets[family] = ip.String()
				t.Logf("selected %s interface=%s index=%d address=%s mtu=%d", family, iface.Name, iface.Index, ip, iface.MTU)
			}
		}
	}
	return targets
}

func TestWindowsUDPTruncationEnvironment(t *testing.T) {
	targets := windowsNativeTargets(t)
	for _, name := range []string{"loopback-ipv4", "loopback-ipv6", "nic-ipv4", "nic-ipv6"} {
		t.Run(name, func(t *testing.T) {
			ip := targets[name]
			if ip == "" {
				t.Skip("NOT EXECUTED: no configured non-loopback address for this family")
			}
			network := "udp6"
			if net.ParseIP(ip).To4() != nil {
				network = "udp4"
			}
			receiver, err := net.ListenPacket(network, net.JoinHostPort(ip, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			sender, err := net.ListenPacket(network, net.JoinHostPort(ip, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			buffer := make([]byte, device.MaxMessageSize)
			for round, size := range []int{2048, 4096, 65000} {
				if _, err = sender.WriteTo(make([]byte, size), receiver.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, addr, err := receiver.ReadFrom(buffer)
				var code windows.Errno
				if !errors.Is(err, windows.WSAEMSGSIZE) || !errors.As(err, &code) || n != len(buffer) || addr != nil {
					t.Fatalf("unexpected native result: size=%d buffer=%d n=%d source=%v err=%v", size, len(buffer), n, addr, err)
				}
				t.Logf("round=%d socket=%s sender=%s datagram=%d buffer=%d n=%d winsock=%d addr=%v error=%T temporary=%v", round, receiver.LocalAddr(), sender.LocalAddr(), size, len(buffer), n, code, addr, err, err.(net.Error).Temporary())
				var syscall *os.SyscallError
				if errors.As(err, &syscall) {
					t.Logf("actual syscall=%s", syscall.Syscall)
				}
				valid := []byte("valid-after-truncation-" + strconv.Itoa(round))
				if _, err = sender.WriteTo(valid, receiver.LocalAddr()); err != nil {
					t.Fatal(err)
				}
				n, _, err = receiver.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], valid) {
					t.Fatalf("same raw socket failed recovery: n=%d err=%v", n, err)
				}
			}
		})
	}
}
