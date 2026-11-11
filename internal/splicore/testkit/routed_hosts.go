package testkit

import (
	"net"
	"runtime"
	"testing"
)

// RoutedHosts are real host addresses outside the test tunnel. Linux campaigns
// own documentation addresses in a private network namespace. Native Windows
// uses configured unicast addresses: gVisor intentionally rejects externally
// received loopback destinations as martian packets.
func RoutedHosts(t *testing.T) []string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return []string{"192.0.2.29", "2001:db8::29"}
	}
	var ipv4, ipv6 string
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
			if ip.To4() != nil && ipv4 == "" {
				ipv4 = ip.String()
			} else if ip.To4() == nil && ipv6 == "" {
				ipv6 = ip.String()
			}
		}
	}
	if ipv4 == "" {
		t.Fatal("qualification needs a configured non-loopback IPv4 address")
	}
	hosts := []string{ipv4}
	if ipv6 != "" {
		hosts = append(hosts, ipv6)
	} else {
		t.Log("NOT EXECUTED: no configured non-loopback IPv6 host target; tunnel IPv6 and loopback IPv6 remain separate required tests")
	}
	t.Logf("owned host targets=%v; no host network mutation", hosts)
	return hosts
}
