package testfixture

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestMieruFixtureLeaseAndKernelSocketOwnership(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		var leases []string
		t.Run(transport, func(t *testing.T) {
			a, b := MieruIntent(t, transport), MieruIntent(t, transport)
			first, second := a.Inbound.Listeners[0].Endpoint, b.Inbound.Listeners[0].Endpoint
			if first == second {
				t.Fatal("simultaneously owned Mieru fixtures share an endpoint")
			}
			for _, endpoint := range []struct {
				host string
				port uint16
			}{{first.Host, first.Port}, {second.Host, second.Port}} {
				port := strconv.Itoa(int(endpoint.port))
				lease := filepath.Join(os.TempDir(), "splicore-peer-leases", transport+"-"+port)
				leases = append(leases, lease)
				if _, err := os.Stat(lease); err != nil {
					t.Fatal("fixture does not retain its peer lease", err)
				}
				address := net.JoinHostPort(endpoint.host, port)
				var socket io.Closer
				var err error
				if transport == "tcp" {
					socket, err = net.Listen("tcp4", address)
				} else {
					socket, err = net.ListenPacket("udp4", address)
				}
				if err != nil {
					t.Fatal("runtime cannot bind the leased fixture endpoint", err)
				}
				if err := socket.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(lease); err != nil {
					t.Fatal("closing a runtime socket retired a live fixture lease", err)
				}
			}
		})
		for _, lease := range leases {
			if _, err := os.Stat(lease); !os.IsNotExist(err) {
				t.Fatal("fixture cleanup did not release its peer lease", err)
			}
		}
	}
}
