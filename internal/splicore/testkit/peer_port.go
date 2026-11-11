package testkit

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// PeerPort reserves a test lease outside OS ephemeral-client port ranges. An
// external process cannot inherit our listener, so allocating port zero and
// closing it races the OS assigning the same port to an unrelated client.
// O_EXCL leases also coordinate different test packages sharing one temp root.
func PeerPort(t *testing.T, network string) int {
	t.Helper()
	return PeerPortAt(t, network, "127.0.0.1")
}

func PeerPortAt(t *testing.T, network, host string) int {
	t.Helper()
	networks := []string{network}
	if network == "tcp+udp" {
		networks = []string{"tcp", "udp"}
	} else if network != "tcp" && network != "udp" {
		t.Fatal("unsupported peer network", network)
	}
	dir := filepath.Join(os.TempDir(), "splicore-peer-leases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for range 256 {
		value, err := rand.Int(rand.Reader, big.NewInt(5000))
		if err != nil {
			t.Fatal(err)
		}
		port := 12000 + int(value.Int64())
		var leases []string
		var sockets []io.Closer
		release := func() {
			for _, socket := range sockets {
				_ = socket.Close()
			}
			sockets = nil
			for _, lease := range leases {
				_ = os.Remove(lease)
			}
		}
		usable := true
		for _, kind := range networks {
			lease := filepath.Join(dir, kind+"-"+strconv.Itoa(port))
			file, err := os.OpenFile(lease, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				release()
				if !os.IsExist(err) {
					t.Fatal(err)
				}
				usable = false
				break
			}
			_ = file.Close()
			leases = append(leases, lease)
		}
		if !usable {
			continue
		}
		address := net.JoinHostPort(host, strconv.Itoa(port))
		family := "6"
		if net.ParseIP(host).To4() != nil {
			family = "4"
		}
		for _, kind := range networks {
			var socket io.Closer
			if kind == "tcp" {
				socket, err = net.Listen(kind+family, address)
			} else {
				socket, err = net.ListenPacket(kind+family, address)
			}
			if err != nil {
				t.Logf("peer port rejected network=%s address=%s cause=%T %v", kind, address, err, err)
				release()
				usable = false
				break
			}
			sockets = append(sockets, socket)
		}
		if !usable {
			continue
		}
		for _, socket := range sockets {
			_ = socket.Close()
		}
		sockets = nil
		t.Cleanup(release)
		t.Logf("external peer lease network=%s address=%s", network, address)
		return port
	}
	t.Fatal(fmt.Errorf("no usable %s peer port after 256 bounded reservations", network))
	return 0
}
