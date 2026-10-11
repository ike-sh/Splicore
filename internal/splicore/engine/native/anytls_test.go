package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func anytlsIntent(t *testing.T) (ports.RuntimeIntent, tlsconfig.Settings) {
	t.Helper()
	in, s := trojanIntent(t)
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: s})
	return in, s
}
func anytlsNode(t *testing.T, in ports.RuntimeIntent, s tlsconfig.Settings, i int) (client.RemoteNode, access.Credential) {
	t.Helper()
	n, c := trojanNode(t, in, s, i)
	n.Protocol = module.Key()
	return n, c
}
func anytlsStart(t *testing.T, ctx context.Context, in ports.RuntimeIntent) *anytlsHandle {
	t.Helper()
	p, err := (AnyTLSCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := p.(*anytlsHandle)
	if err = h.Start(context.Background()); err != nil {
		h.Close(context.Background())
		t.Fatal(err)
	}
	h.Activate()
	t.Cleanup(func() { h.Close(context.Background()) })
	return h
}
func anytlsTCP(t *testing.T, d ports.ClientDialer, dst access.Endpoint) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	for _, size := range []int{1, 93, 65535, 65536, 131073, 3 << 20} {
		data := bytes.Repeat([]byte{byte(size)}, size)
		result := make(chan error, 1)
		go func() { _, err := c.Write(data); result <- err }()
		got := make([]byte, size)
		if _, err = io.ReadFull(c, got); err != nil {
			t.Fatal(size, err)
		}
		if err = <-result; err != nil || !bytes.Equal(data, got) {
			t.Fatal("TCP integrity", size, err)
		}
	}
	for i := 0; i < 50; i++ {
		data := []byte{byte(i)}
		c.Write(data)
		got := make([]byte, 1)
		if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(data, got) {
			t.Fatal("small writes", err)
		}
	}
}
func anytlsUDP(t *testing.T, d ports.ClientDialer, dst access.Endpoint, sizes ...int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(10 * time.Second))
	if len(sizes) == 0 {
		sizes = []int{0, 1, 512, 4096, 32768}
	}
	for _, size := range sizes {
		data := bytes.Repeat([]byte{byte(size)}, size)
		if n, err := p.WriteTo(data, netaddr.UDP(dst)); err != nil || n != size {
			t.Fatal("UDP write", err)
		}
		got := make([]byte, 65535)
		n, a, err := p.ReadFrom(got)
		if err != nil || !bytes.Equal(got[:n], data) {
			t.Fatal("UDP integrity", size, err)
		}
		if a == nil || netaddrEndpoint(a).Port != dst.Port {
			t.Fatal("UDP destination lost")
		}
	}
}
func TestAnyTLSNativeTLSMultiUserTCPUDPReuse(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := anytlsIntent(t)
	h := anytlsStart(t, ctx, in)
	tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
	udp := trojanUDP(t)
	for i := range 2 {
		for _, mode := range []string{"connect", "non_connect"} {
			n, c := anytlsNode(t, in, s, i)
			n.Options.Data, _ = json.Marshal(module.ClientOptions{UDP: true, UOTMode: mode, MultiplexStreams: 64})
			d, err := (AnyTLSOutboundFactory{}).Build(ctx, n, c)
			if err != nil {
				t.Fatal(err)
			}
			anytlsTCP(t, d, tcp)
			anytlsUDP(t, d, udp)
			for j := 0; j < 5; j++ {
				anytlsTCP(t, d, tcp)
			}
			if d.(*anytlsDialer).pool.State().LastSequence != 1 {
				t.Fatal("healthy session not reused")
			}
			d.Close()
			if h.BindingStats(in.Bindings[i].ID).Upload == 0 || h.BindingStats(in.Bindings[i].ID).Download == 0 {
				t.Fatal("unattributed user")
			}
		}
	}
	h.Close(context.Background())
	h.mu.Lock()
	retained := len(h.connections)
	h.mu.Unlock()
	if retained != 0 || h.Stats().Active != 0 {
		t.Fatal("retained runtime resources")
	}
}
func TestAnyTLSTLSAuthenticationAndFailureIsolation(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := anytlsIntent(t)
	anytlsStart(t, ctx, in)
	target := netaddrEndpoint(testfixture.TCP(t).Addr())
	for _, kind := range []string{"wrong-sni", "wrong-ca", "system-untrusted", "wrong-password"} {
		t.Run(kind, func(t *testing.T) {
			n, c := anytlsNode(t, in, s, 0)
			switch kind {
			case "wrong-sni":
				n.Security.TLS.ServerName = "wrong.test"
			case "wrong-ca":
				n.Security.TLS.CACertificate = testkit.TLS(t).CACertificate
			case "system-untrusted":
				n.Security.TLS.Trust = "system"
				n.Security.TLS.CACertificate = ""
			case "wrong-password":
				c.Payload = access.PasswordPayload{Password: secret.New("synthetic-wrong-password")}
			}
			d, err := (AnyTLSOutboundFactory{}).Build(ctx, n, c)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if conn, err := d.DialContext(context.Background(), target); err == nil {
				conn.Close()
				t.Fatal("TLS/auth accepted")
			} else if strings.Contains(err.Error(), "synthetic-wrong-password") {
				t.Fatal("secret leak")
			}
		})
	}
	n, c := anytlsNode(t, in, s, 0)
	n.Options.Data = json.RawMessage(`{"udp":true,"multiplex_streams":64}`)
	d, err := (AnyTLSOutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if conn, err := d.DialContext(context.Background(), access.Endpoint{Host: "127.0.0.1", Port: 1}); err == nil {
		conn.Close()
		t.Fatal("failed destination accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); anytlsTCP(t, d, target) }()
	}
	wg.Wait()
}

func TestAnyTLSOwnedLifecycle25(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(testfixture.TCP(t).Addr())
	udp := trojanUDP(t)
	runtime.GC()
	runtime.GC()
	start := runtime.NumGoroutine()
	fdStart, _ := os.ReadDir("/proc/self/fd")
	for i := 0; i < 25; i++ {
		in, s := anytlsIntent(t)
		h := anytlsStart(t, ctx, in)
		n, c := anytlsNode(t, in, s, i%2)
		d, err := (AnyTLSOutboundFactory{}).Build(ctx, n, c)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := d.DialContext(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		conn.Write([]byte("owned"))
		b := make([]byte, 5)
		if _, err = io.ReadFull(conn, b); err != nil || string(b) != "owned" {
			t.Fatal(err)
		}
		conn.Close()
		anytlsUDP(t, d, udp, 0, 512)
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		if err = h.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if d.(*anytlsDialer).pool.State().Sessions != 0 {
			t.Fatal("client session retained")
		}
		h.mu.Lock()
		retained := len(h.connections)
		h.mu.Unlock()
		if retained != 0 || h.Stats().Active != 0 {
			t.Fatal("server resource retained")
		}
	}
	// TCP echo's io.Copy can cache splice pipes in the Go runtime. Collect the
	// unused cache at both samples; owned sockets have already closed and joined.
	runtime.GC()
	runtime.GC()
	end := time.Now().Add(time.Second)
	fdEnd, _ := os.ReadDir("/proc/self/fd")
	for (runtime.NumGoroutine() > start+2 || len(fdEnd) > len(fdStart)) && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
		fdEnd, _ = os.ReadDir("/proc/self/fd")
	}
	if runtime.NumGoroutine() > start+2 || len(fdEnd) > len(fdStart) {
		t.Fatalf("owned lifecycle grew: goroutines %d -> %d; fd %d -> %d", start, runtime.NumGoroutine(), len(fdStart), len(fdEnd))
	}
	t.Logf("25 joined lifecycles; goroutines %d -> %d; fd %d -> %d; retained sessions/streams=0", start, runtime.NumGoroutine(), len(fdStart), len(fdEnd))
}

func TestAnyTLSIPv6TCPUDPAndDomainUDP(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 unavailable")
	}
	defer l.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer c.Close(); io.Copy(c, c) }()
		}
	}()
	t.Cleanup(func() { l.Close(); wg.Wait() })
	p, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	packetDone := make(chan struct{})
	go func() {
		defer close(packetDone)
		b := make([]byte, 65535)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { p.Close(); <-packetDone })
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := anytlsIntent(t)
	anytlsStart(t, ctx, in)
	n, c := anytlsNode(t, in, s, 0)
	d, err := (AnyTLSOutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	anytlsTCP(t, d, netaddrEndpoint(l.Addr()))
	anytlsUDP(t, d, netaddrEndpoint(p.LocalAddr()))
	dst := trojanUDP(t)
	dst.Host = "localhost"
	anytlsUDP(t, d, dst, 0, 512, 8192)
}
