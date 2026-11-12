package testkit

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

// DualPeerPort owns real TCP and UDP sockets at one literal IP and OS-selected
// port. ReleaseSockets is the explicit handoff immediately before child Start.
// File leases coordinate cooperating test processes through child shutdown;
// they cannot eliminate interference by an unrelated process in that window.
type DualPeerPort struct {
	Host    string
	Port    int
	sockets []io.Closer
	once    sync.Once
}

func (p *DualPeerPort) Address() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }
func (p *DualPeerPort) ReleaseSockets() {
	p.once.Do(func() {
		for _, socket := range p.sockets {
			_ = socket.Close()
		}
	})
}

func ReserveDualPeerPort(t *testing.T, host string) *DualPeerPort {
	t.Helper()
	PeerPortEnvironment(t)
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatal("peer lease requires a literal IP")
	}
	family := "6"
	if ip.To4() != nil {
		family = "4"
	}
	dir := filepath.Join(os.TempDir(), "splicore-peer-leases")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 64; attempt++ {
		p := &DualPeerPort{Host: host}
		first, second := "tcp", "udp"
		// A TCP allocator may repeatedly select ports reserved only for UDP on
		// Windows. The alternate OS UDP allocator is still verified for TCP;
		// no port range, random fixed port, reuse option or system policy changes.
		if attempt%2 == 0 {
			first, second = second, first
		}
		bind := func(network, address string) (io.Closer, int, error) {
			if network == "tcp" {
				s, err := net.Listen(network+family, address)
				if err != nil {
					return nil, 0, err
				}
				return s, s.Addr().(*net.TCPAddr).Port, nil
			}
			s, err := net.ListenPacket(network+family, address)
			if err != nil {
				return nil, 0, err
			}
			return s, s.LocalAddr().(*net.UDPAddr).Port, nil
		}
		one, port, err := bind(first, net.JoinHostPort(host, "0"))
		if err != nil {
			t.Logf("dual_peer_candidate attempt=%d network=%s error=%v", attempt, first, err)
			continue
		}
		p.Port = port
		p.sockets = append(p.sockets, one)
		two, _, err := bind(second, p.Address())
		if err != nil {
			t.Logf("dual_peer_candidate attempt=%d first=%s address=%s network=%s error=%v", attempt, first, p.Address(), second, err)
			p.ReleaseSockets()
			continue
		}
		p.sockets = append(p.sockets, two)
		var files []string
		for _, kind := range []string{"tcp", "udp"} {
			path := filepath.Join(dir, kind+"-"+strconv.Itoa(port))
			f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				err = e
				break
			}
			_ = f.Close()
			files = append(files, path)
		}
		releaseFiles := func() {
			for _, path := range files {
				_ = os.Remove(path)
			}
		}
		if err != nil {
			p.ReleaseSockets()
			releaseFiles()
			if !errors.Is(err, os.ErrExist) {
				t.Fatal(err)
			}
			t.Logf("dual_peer_candidate attempt=%d address=%s file_lease_error=%v", attempt, p.Address(), err)
			continue
		}
		t.Cleanup(func() { p.ReleaseSockets(); releaseFiles() })
		t.Logf("dual_peer_reserved attempt=%d address=%s TCP=bound UDP=bound handoff=pending", attempt, p.Address())
		return p
	}
	t.Fatal(fmt.Errorf("no TCP+UDP peer endpoint after 64 OS-selected candidates on %s", host))
	return nil
}
