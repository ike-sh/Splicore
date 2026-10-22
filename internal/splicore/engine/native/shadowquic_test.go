//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowquic"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

const (
	sqUser = "phase30-native-synthetic-username"
	sqPass = "phase30-native-synthetic-password"
	sqName = "camouflage.test"
)

func sqServer(t *testing.T, ctx context.Context) (*shadowQUICHandle, ports.RuntimeIntent) {
	t.Helper()
	in := testfixture.MieruIntent(t, "udp")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{ServerName: sqName, Camouflage: access.Endpoint{Host: "127.0.0.1", Port: 9}})
	in.Credentials[0].Payload = access.UsernamePasswordPayload{Username: secret.New(sqUser), Password: secret.New(sqPass)}
	p, e := (ShadowQUICCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := p.(*shadowQUICHandle)
	if e = h.Start(ctx); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := h.Close(ctx); e != nil {
			t.Error(e)
		}
	})
	return h, in
}

func sqNode(t *testing.T, in ports.RuntimeIntent, user int) (client.RemoteNode, access.Credential) {
	t.Helper()
	c := in.Credentials[user]
	id, e := identity.NewID()
	if e != nil {
		t.Fatal(e)
	}
	c.OwnerAccountID = nil
	c.OwnerNodeID = &id
	n := client.RemoteNode{ID: id, Name: "synthetic-shadowquic", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: c.ID, Transport: client.Transport{Kind: "quic"}, Security: client.Security{Kind: "jls", TLS: access.ClientTLS{Enabled: true, ServerName: sqName, ALPN: []string{"h3"}, Trust: "jls"}}, Options: client.Options{Schema: 1, Data: []byte(`{"handshake_timeout":1}`)}}
	return n, c
}

func sqExchange(c net.Conn, size int, half bool) error {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*17 + size)
	}
	result := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); {
			end := min(len(payload), off+211)
			if _, e := c.Write(payload[off:end]); e != nil {
				result <- e
				return
			}
			off = end
		}
		if half {
			w, ok := c.(interface{ CloseWrite() error })
			if !ok {
				result <- errors.New("missing half close")
				return
			}
			result <- w.CloseWrite()
			return
		}
		result <- nil
	}()
	b := make([]byte, size)
	if _, e := io.ReadFull(c, b); e != nil {
		return e
	}
	if !bytes.Equal(payload, b) {
		return errors.New("byte mismatch")
	}
	if e := <-result; e != nil {
		return e
	}
	if half {
		var b [1]byte
		if _, e := c.Read(b[:]); e != io.EOF {
			return errors.New("missing EOF")
		}
	}
	return nil
}

func sqUDPExchange(p net.PacketConn, dst access.Endpoint, sizes []int) error {
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(4 * time.Second))
	for _, size := range sizes {
		payload := bytes.Repeat([]byte{byte(size * 19)}, size)
		if _, e := p.WriteTo(payload, netaddr.UDP(dst)); e != nil {
			return e
		}
		b := make([]byte, 1500)
		n, a, e := p.ReadFrom(b)
		if e != nil {
			return e
		}
		d, e := netaddr.From(a)
		if e != nil || d != dst || !bytes.Equal(payload, b[:n]) {
			return errors.New("UDP byte/address mismatch")
		}
	}
	return nil
}

func TestShadowQUICNativeMultiUserLifecycleAndBounds(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(testfixture.TCP(t).Addr())
	udp := trojanUDP(t)
	udp.Host = "localhost"
	runtime.GC()
	before := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	for range 3 {
		h, in := sqServer(t, ctx)
		for user := range 2 {
			n, c := sqNode(t, in, user)
			d, e := (ShadowQUICOutboundFactory{}).Build(ctx, n, c)
			if e != nil {
				t.Fatal(e)
			}
			conn, e := d.DialContext(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			if e = sqExchange(conn, 65536, true); e != nil {
				t.Fatal(e)
			}
			p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
			if e != nil {
				t.Fatal(e)
			}
			if e = sqUDPExchange(p, udp, []int{0, 1, 1199, 1200}); e != nil {
				t.Fatal(e)
			}
			d.Close()
			stats := h.BindingStats(in.Bindings[user].ID)
			if stats.Upload < 65536 || stats.Download < 65536 {
				t.Fatal("attribution", stats)
			}
		}
		if e := h.Close(ctx); e != nil {
			t.Fatal(e)
		}
		if h.Health(ctx) == nil {
			t.Fatal("stale health")
		}
		if h.Start(ctx) == nil {
			t.Fatal("closed restart")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before+8 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) > len(fds)+4 || runtime.NumGoroutine() > before+8 {
		t.Fatal("resource growth", len(fds), len(after), before, runtime.NumGoroutine())
	}
}

func TestShadowQUICNativeBindOwnershipAndPolicy(t *testing.T) {
	backend := &trustTunnelDenyBackend{}
	factory := underlay.NewWithBackend(backend)
	ctx := underlay.WithFactory(context.Background(), factory)
	lease, e := factory.Begin(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	h, in := sqServer(t, ctx)
	if _, e := (ShadowQUICCompiler{}).Compile(ctx, func() ports.RuntimeIntent {
		bad := in
		bad.Bindings = append([]access.Binding(nil), in.Bindings...)
		bad.Bindings[0].AccountID = in.Bindings[1].AccountID
		return bad
	}()); e == nil {
		t.Fatal("ownership bypass")
	}
	p, e := (ShadowQUICCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close(ctx)
	if e = p.(ports.RuntimeHandle).Start(ctx); e == nil {
		t.Fatal("failed bind accepted")
	}
	n, c := sqNode(t, in, 0)
	d, e := (ShadowQUICOutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	conn, e := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: 443})
	if e == nil {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte{42})
		var b [1]byte
		if _, e = conn.Read(b[:]); e == nil {
			t.Fatal("policy bypass")
		}
		conn.Close()
	}
	if backend.attempts.Load() == 0 {
		t.Fatal("ServerTarget bypass")
	}
	h.Close(ctx)
}

func TestShadowQUICNativeConcurrentShutdown(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	h, in := sqServer(t, ctx)
	n, c := sqNode(t, in, 0)
	d, e := (ShadowQUICOutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	target := netaddrEndpoint(testfixture.TCP(t).Addr())
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 3 {
				conn, e := d.DialContext(ctx, target)
				if e == nil {
					conn.Close()
				}
			}
		})
	}
	h.Close(ctx)
	d.Close()
	wg.Wait()
}
