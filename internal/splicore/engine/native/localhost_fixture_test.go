package native

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

// Own both loopback families at the same port. A domain UDP dial can select
// either family without the TCP fallback that an IPv4-only target relies on.
func localhostUDP(t *testing.T) access.Endpoint {
	t.Helper()
	packet := loopbackUDPEcho(t, "udp4", "127.0.0.1:0")
	port := packet.LocalAddr().(*net.UDPAddr).Port
	loopbackUDPEcho(t, "udp6", net.JoinHostPort("::1", fmt.Sprint(port)))
	return access.Endpoint{Host: "localhost", Port: uint16(port)}
}

func loopbackUDPEcho(t *testing.T, network, address string) net.PacketConn {
	t.Helper()
	packet, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s fixture listening on %s", network, packet.LocalAddr())
	done := make(chan struct{})
	go func() {
		defer close(done)
		var first sync.Once
		buffer := make([]byte, 65535)
		for {
			n, peer, err := packet.ReadFrom(buffer)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("%s fixture read: %v", network, err)
				}
				return
			}
			first.Do(func() { t.Logf("%s fixture received from %s, bytes=%d", network, peer, n) })
			written, err := packet.WriteTo(buffer[:n], peer)
			if err != nil || written != n {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("%s fixture echo: wrote %d/%d: %v", network, written, n, err)
				}
				return
			}
		}
	}()
	t.Cleanup(func() {
		if err := packet.Close(); err != nil {
			t.Error(err)
		}
		<-done
	})
	return packet
}

func TestLocalhostUDPAddressFamiliesAndCleanup(t *testing.T) {
	var destination access.Endpoint
	if !t.Run("owner", func(t *testing.T) {
		destination = localhostUDP(t)
		for _, target := range []struct{ network, host string }{
			{"udp4", "127.0.0.1"}, {"udp6", "::1"}, {"udp", "localhost"},
		} {
			t.Run(target.network, func(t *testing.T) {
				peer, err := net.DialTimeout(target.network, net.JoinHostPort(target.host, fmt.Sprint(destination.Port)), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				t.Logf("%s local=%s remote=%s", target.network, peer.LocalAddr(), peer.RemoteAddr())
				if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if err := peer.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1200)
				_, err = peer.Read(buffer)
				var timeout net.Error
				if !errors.As(err, &timeout) || !timeout.Timeout() {
					t.Fatal("expired read deadline", err)
				}
				if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				for _, size := range []int{0, 1, 1200} {
					want := bytes.Repeat([]byte{71}, size)
					if n, err := peer.Write(want); err != nil || n != size {
						t.Fatal("UDP write", size, n, err)
					}
					n, err := peer.Read(buffer)
					if err != nil || !bytes.Equal(buffer[:n], want) {
						t.Fatal("UDP echo", size, n, err)
					}
				}
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
				if _, err := peer.Write([]byte{1}); !errors.Is(err, net.ErrClosed) {
					t.Fatal("closed UDP connection accepted write", err)
				}
			})
		}
	}) {
		return
	}
	// Owner cleanup has closed both sockets and joined both echo workers.
	for _, target := range []struct{ network, host string }{{"udp4", "127.0.0.1"}, {"udp6", "::1"}} {
		packet, err := net.ListenPacket(target.network, net.JoinHostPort(target.host, fmt.Sprint(destination.Port)))
		if err != nil {
			t.Fatal("fixture retained port", target.network, err)
		}
		if err := packet.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoopbackTCPAddressFamiliesAndCleanup(t *testing.T) {
	for _, target := range []struct{ network, host string }{{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}} {
		t.Run(target.network, func(t *testing.T) {
			listener, err := net.Listen(target.network, net.JoinHostPort(target.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			result := make(chan error, 1)
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err == nil {
					defer conn.Close()
					err = conn.SetDeadline(time.Now().Add(time.Second))
					buffer := make([]byte, 4)
					if err == nil {
						_, err = io.ReadFull(conn, buffer)
					}
					if err == nil {
						_, err = io.CopyN(conn, bytes.NewReader(buffer), int64(len(buffer)))
					}
				}
				result <- err
			}()
			t.Cleanup(func() { listener.Close(); <-done })
			peer, err := net.DialTimeout(target.network, listener.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			t.Logf("%s listener=%s local=%s remote=%s", target.network, listener.Addr(), peer.LocalAddr(), peer.RemoteAddr())
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := peer.Write([]byte("echo")); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 4)
			if _, err := io.ReadFull(peer, buffer); err != nil || string(buffer) != "echo" {
				t.Fatal("TCP echo", string(buffer), err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
				t.Fatal("closed TCP listener accepted connection", err)
			}
		})
	}
}
