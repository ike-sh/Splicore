package testkit

import (
	"crypto/rand"
	"fmt"
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
	if network != "tcp" && network != "udp" {
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
		lease := filepath.Join(dir, network+"-"+strconv.Itoa(port))
		file, err := os.OpenFile(lease, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = file.Close()
		address := net.JoinHostPort(host, strconv.Itoa(port))
		family := "6"
		if net.ParseIP(host).To4() != nil {
			family = "4"
		}
		if network == "tcp" {
			listener, err := net.Listen(network+family, address)
			if err != nil {
				_ = os.Remove(lease)
				continue
			}
			_ = listener.Close()
		} else {
			packet, err := net.ListenPacket(network+family, address)
			if err != nil {
				_ = os.Remove(lease)
				continue
			}
			_ = packet.Close()
		}
		t.Cleanup(func() { _ = os.Remove(lease) })
		t.Logf("external peer lease network=%s address=%s", network, address)
		return port
	}
	t.Fatal(fmt.Errorf("no usable %s peer port after 256 bounded reservations", network))
	return 0
}
