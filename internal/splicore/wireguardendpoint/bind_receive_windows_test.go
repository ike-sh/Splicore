package wireguardendpoint

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type scriptedUDPRead struct {
	net.PacketConn
	read func([]byte) (int, net.Addr, error)
}

func (s scriptedUDPRead) ReadFrom(b []byte) (int, net.Addr, error) { return s.read(b) }

func TestWindowsUDPReceiveErrorSemantics(t *testing.T) {
	wrapped := func(err error) error {
		return &net.OpError{Op: "read", Net: "udp", Err: &os.SyscallError{Syscall: "wsarecvfrom", Err: err}}
	}
	t.Run("discard-partial-datagrams", func(t *testing.T) {
		calls := 0
		addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
		c := wrapUDPReceiveConn(scriptedUDPRead{read: func(b []byte) (int, net.Addr, error) {
			calls++
			if calls <= 3 {
				return copy(b, "partial"), nil, wrapped(windows.WSAEMSGSIZE)
			}
			if calls != 4 {
				t.Fatal("unexpected extra read")
			}
			return copy(b, "valid"), addr, nil
		}})
		b := make([]byte, 16)
		n, source, err := c.ReadFrom(b)
		if err != nil || calls != 4 || n != 5 || source != addr || string(b[:n]) != "valid" {
			t.Fatalf("read: n=%d source=%v err=%v calls=%d", n, source, err, calls)
		}
	})
	for _, entry := range []struct {
		name string
		err  error
	}{
		{"closed", wrapped(net.ErrClosed)},
		{"canceled", wrapped(context.Canceled)},
		{"deadline", wrapped(os.ErrDeadlineExceeded)},
		{"permanent", wrapped(windows.WSAENOTSOCK)},
		{"reset", wrapped(windows.WSAECONNRESET)},
		{"temporary", wrapped(windows.WSAEWOULDBLOCK)},
		{"text-only", errors.New("WSAEMSGSIZE 10040")},
	} {
		t.Run(entry.name, func(t *testing.T) {
			calls := 0
			c := wrapUDPReceiveConn(scriptedUDPRead{read: func([]byte) (int, net.Addr, error) {
				calls++
				if calls > 1 {
					t.Fatal("non-WSAEMSGSIZE error retried")
				}
				return 7, nil, entry.err
			}})
			n, addr, err := c.ReadFrom(make([]byte, 16))
			if n != 7 || addr != nil || err != entry.err || calls != 1 {
				t.Fatalf("error changed: n=%d addr=%v err=%v calls=%d", n, addr, err, calls)
			}
		})
	}
}

type udpTruncation struct {
	n    int
	addr net.Addr
	err  error
}

// Observe the real socket below the production wrapper without changing its
// results. Installation happens in Open, before the Device starts its worker.
type observedUDPConn struct {
	net.PacketConn
	reads     atomic.Int32
	truncated chan udpTruncation
}

func (c *observedUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.reads.Add(1)
	n, addr, err := c.PacketConn.ReadFrom(b)
	if errors.Is(err, windows.WSAEMSGSIZE) {
		c.truncated <- udpTruncation{n, addr, err}
	}
	return n, addr, err
}

type observedUDPBind struct {
	*udpBind
	observed *observedUDPConn
	opens    int
}

func (b *observedUDPBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.udpBind.Open(port)
	if err == nil {
		b.opens++
		c := b.socket.(*udpReceiveConn)
		b.observed = &observedUDPConn{PacketConn: c.PacketConn, truncated: make(chan udpTruncation, 4)}
		c.PacketConn = b.observed
	}
	return fns, actual, err
}

func closeWindowsTestDevice(t *testing.T, d *device.Device) {
	t.Helper()
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Device.Close did not join")
	}
	select {
	case <-d.Wait():
	default:
		t.Fatal("Device.Wait not closed")
	}
}

func TestWindowsWireGuardOversizedReceiveRecovery(t *testing.T) {
	var private, public [2]string
	for i := range private {
		secret, pub, err := GenerateKeys()
		if err != nil {
			t.Fatal(err)
		}
		key, _ := E.DecodeKey(secret)
		private[i] = hex.EncodeToString(key[:])
		key, _ = E.DecodeKey(pub)
		public[i] = hex.EncodeToString(key[:])
	}
	var devices [2]*device.Device
	var binds [2]*observedUDPBind
	var tuns [2]*memoryTUN
	var starts, stops [2]atomic.Int32
	for i := range devices {
		protected, err := underlay.New().New(underlay.Scope{Purpose: underlay.ProxyUnderlay})
		if err != nil {
			t.Fatal(err)
		}
		binds[i] = &observedUDPBind{udpBind: &udpBind{protected: protected, ctx: context.Background()}}
		tuns[i] = newMemoryTUN(1420)
		logger := &device.Logger{Errorf: func(string, ...any) {}, Verbosef: func(format string, _ ...any) {
			if strings.HasPrefix(format, "Routine: receive incoming ") {
				if strings.HasSuffix(format, "- started") {
					starts[i].Add(1)
				} else if strings.HasSuffix(format, "- stopped") {
					stops[i].Add(1)
				}
			}
		}}
		d := device.NewDevice(tuns[i], binds[i], logger)
		devices[i] = d
		t.Cleanup(func() { closeWindowsTestDevice(t, d) })
		cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.34.0.%d/32\n", private[i], public[i^1], (i^1)+1)
		if d.IpcSet(cfg) != nil {
			t.Fatal("device configuration rejected")
		}
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
	}
	for i, d := range devices {
		port := binds[i^1].socket.LocalAddr().(*net.UDPAddr).Port
		if d.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=127.0.0.1:%d\n", public[i^1], port)) != nil {
			t.Fatal("peer endpoint rejected")
		}
	}
	exchange := func() {
		t.Helper()
		for i := range devices {
			packet := tuntest.Ping(netip.AddrFrom4([4]byte{10, 34, 0, byte((i ^ 1) + 1)}), netip.AddrFrom4([4]byte{10, 34, 0, byte(i + 1)}))
			if _, err := (stackDevice{tuns[i]}).Write(packet); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-tuns[i^1].decrypted:
				if !bytes.Equal(got, packet) {
					t.Fatal("authenticated plaintext changed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("authenticated traffic did not recover")
			}
		}
	}
	exchange()
	b := binds[1]
	socket := b.socket
	raw := b.observed.PacketConn
	sender, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	destination := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: socket.LocalAddr().(*net.UDPAddr).Port}
	for _, sizes := range [][]int{{2048}, {2017, 4096, 65507}} {
		for _, size := range sizes {
			if _, err := sender.WriteTo(make([]byte, size), destination); err != nil {
				t.Fatal(err)
			}
		}
		for range sizes {
			select {
			case got := <-b.observed.truncated:
				if got.n != device.MaxMessageSize || got.addr != nil {
					t.Fatalf("unexpected truncation: n=%d addr=%v", got.n, got.addr)
				}
				t.Logf("real WSAEMSGSIZE: n=%d addr=%v Temporary=%v", got.n, got.addr, got.err.(net.Error).Temporary())
				for e := got.err; e != nil; e = errors.Unwrap(e) {
					t.Logf("error chain: %T", e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("real socket did not report WSAEMSGSIZE")
			}
		}
		// A consumed datagram leads to a blocking socket read, not polling.
		time.Sleep(25 * time.Millisecond)
		reads := b.observed.reads.Load()
		time.Sleep(25 * time.Millisecond)
		if b.observed.reads.Load() != reads || stops[1].Load() != 0 {
			t.Fatal("worker stopped or receive loop spun while idle")
		}
		exchange()
		if b.socket != socket || b.observed.PacketConn != raw || b.opens != 1 || starts[1].Load() != 1 || stops[1].Load() != 0 || devices[1].Bind() != b {
			t.Fatal("Device/Bind/socket/worker replaced or stopped")
		}
	}
	// BindClose joins the receive worker; Device.Close joins all remaining work.
	bindClosed := make(chan error, 1)
	go func() { bindClosed <- devices[1].BindClose() }()
	select {
	case err := <-bindClosed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("BindClose did not join")
	}
	for i, d := range devices {
		closeWindowsTestDevice(t, d)
		if binds[i].resources() != 0 || starts[i].Load() != 1 || stops[i].Load() != 1 {
			t.Fatal("socket or receive worker not cleaned up")
		}
		_, _, err := binds[i].observed.PacketConn.ReadFrom(make([]byte, 1))
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("underlying socket still open: %v", err)
		}
	}
	t.Log("same Device/Bind/socket/worker recovered; BindClose, Device.Close and Wait joined; raw sockets closed")
}
