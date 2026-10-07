package native

import (
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/trojan/wire"
)

func trojanIntent(t *testing.T) (ports.RuntimeIntent, tlsconfig.Settings) {
	t.Helper()
	in := testfixture.MieruIntent(t, "tcp")
	material := testkit.TLSForName(t, "trojan.synthetic.test")
	in.Inbound.Protocol = module.Key()
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: material})
	for i := range in.Credentials {
		password := in.Credentials[i].Payload.(access.UsernamePasswordPayload).Password
		in.Credentials[i].Kind = access.Password
		in.Credentials[i].Payload = access.PasswordPayload{Password: password}
	}
	return in, material
}
func trojanNode(t *testing.T, in ports.RuntimeIntent, material tlsconfig.Settings, index int) (client.RemoteNode, access.Credential) {
	t.Helper()
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	n := client.RemoteNode{ID: id, Name: "synthetic-Trojan", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}}, Options: client.Options{Schema: 1, Data: json.RawMessage(`{"udp":true}`)}}
	c := in.Credentials[index]
	c.ID = cid
	c.OwnerAccountID = nil
	c.OwnerNodeID = &id
	return n, c
}
func trojanUDP(t *testing.T) access.Endpoint {
	t.Helper()
	p, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { _ = p.Close(); <-done })
	return netaddrEndpoint(p.LocalAddr())
}
func netaddrEndpoint(a net.Addr) access.Endpoint { v, _ := netaddr.From(a); return v }
func trojanTransfer(t *testing.T, d ports.ClientDialer, tcp, udp access.Endpoint) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := d.DialContext(ctx, tcp)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("Trojan-payload-integrity"), 4096)
	done := make(chan error, 1)
	go func() { _, e := c.Write(payload); done <- e }()
	b := make([]byte, len(payload))
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil || !bytes.Equal(b, payload) {
		t.Fatal("TCP integrity")
	}
	_ = c.Close()
	p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
	if e != nil {
		t.Fatal(e)
	}
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	for _, size := range []int{0, 1, 8192, 32768} {
		data := bytes.Repeat([]byte{42}, size)
		if n, e := p.WriteTo(data, netaddr.UDP(udp)); e != nil || n != size {
			t.Fatal("UDP write", e)
		}
		b := make([]byte, 65535)
		n, a, e := p.ReadFrom(b)
		if e != nil || !bytes.Equal(b[:n], data) || netaddrEndpoint(a) != udp {
			t.Fatal("UDP integrity", size, e)
		}
	}
	_ = p.Close()
}
func TestTrojanNativeTLSMultiUserLifecycle(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, material := trojanIntent(t)
	prepared, e := (TrojanCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := prepared.(*trojanHandle)
	defer h.Close(context.Background())
	if e = h.Start(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
	udp := trojanUDP(t)
	for i := range 2 {
		n, c := trojanNode(t, in, material, i)
		d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
		if e != nil {
			t.Fatal(e)
		}
		trojanTransfer(t, d, tcp, udp)
		_ = d.Close()
		if h.BindingStats(in.Bindings[i].ID).Upload == 0 || h.BindingStats(in.Bindings[i].ID).Download == 0 {
			t.Fatal("user statistics unattributed")
		}
	}
	if e = h.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.mu.Lock()
	retained := len(h.connections)
	h.mu.Unlock()
	if retained != 0 || h.Stats().Active != 0 {
		t.Fatal("retained sessions")
	}
}
func TestTrojanTLSVerificationWrongAuthAndPortConflict(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, material := trojanIntent(t)
	prepared, e := (TrojanCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := prepared.(*trojanHandle)
	defer h.Close(context.Background())
	if h.Start(context.Background()) != nil {
		t.Fatal("start")
	}
	h.Activate()
	target := netaddrEndpoint(testfixture.TCP(t).Addr())
	for _, kind := range []string{"wrong-sni", "wrong-ca", "system-untrusted", "wrong-password", "expired", "not-yet-valid"} {
		t.Run(kind, func(t *testing.T) {
			n, c := trojanNode(t, in, material, 0)
			switch kind {
			case "wrong-sni":
				n.Security.TLS.ServerName = "wrong.synthetic.test"
			case "wrong-ca":
				n.Security.TLS.CACertificate = testkit.TLS(t).CACertificate
			case "system-untrusted":
				n.Security.TLS.Trust = "system"
				n.Security.TLS.CACertificate = ""
			case "wrong-password":
				c.Payload = access.PasswordPayload{Password: secret.New("synthetic-invalid-password")}
			}
			d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
			if e != nil {
				t.Fatal(e)
			}
			defer d.Close()
			if kind == "expired" {
				d.(*trojanDialer).tls.Time = func() time.Time { return time.Now().Add(24 * time.Hour) }
			}
			if kind == "not-yet-valid" {
				d.(*trojanDialer).tls.Time = func() time.Time { return time.Now().Add(-24 * time.Hour) }
			}
			deadline, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, e := d.DialContext(deadline, target)
			if kind == "wrong-password" && e == nil {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write([]byte("expected-rejection"))
				_, e = conn.Read(make([]byte, 32))
			}
			if e == nil {
				t.Fatal("TLS/auth rejection did not occur")
			}
			if strings.Contains(e.Error(), "synthetic-invalid-password") {
				t.Fatal("error secret leak")
			}
		})
	}
	second, e := (TrojanCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close(context.Background())
	if e = second.(ports.RuntimeHandle).Start(context.Background()); e == nil {
		t.Fatal("listener conflict admitted")
	}
}

func TestTrojanInvalidTLSMaterial(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, kind := range []string{"missing-cert", "missing-key", "mismatch", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			in, s := trojanIntent(t)
			switch kind {
			case "missing-cert":
				s.CertificateFile += ".missing"
			case "missing-key":
				s.PrivateKeyFile += ".missing"
			case "mismatch":
				s.PrivateKeyFile = testkit.TLS(t).PrivateKeyFile
			case "malformed":
				if e := os.WriteFile(s.PrivateKeyFile, []byte("synthetic malformed key"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: s})
			if h, e := (TrojanCompiler{}).Compile(ctx, in); e == nil {
				_ = h.Close(context.Background())
				t.Fatal("invalid material prepared")
			}
		})
	}
}

func TestTrojanClientParentInterruptsPendingTLS(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := trojanIntent(t)
	n, c := trojanNode(t, in, s, 0)
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	n.Endpoint = netaddrEndpoint(l.Addr())
	d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		raw, e := l.Accept()
		if e == nil {
			accepted <- raw
		}
	}()
	done := make(chan error, 1)
	go func() {
		conn, e := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: 443})
		if conn != nil {
			_ = conn.Close()
		}
		done <- e
	}()
	var raw net.Conn
	select {
	case raw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("underlay not admitted")
	}
	defer raw.Close()
	closed := make(chan struct{})
	go func() { _ = d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("parent failed to join pending handshake")
	}
	if e = <-done; e == nil {
		t.Fatal("stalled TLS connection published")
	}
}

func TestTrojanTCPHalfCloseAndServerFirst(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := trojanIntent(t)
	prepared, e := (TrojanCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := prepared.(*trojanHandle)
	defer h.Close(context.Background())
	if e = h.Start(ctx); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, e = c.Write([]byte("server-first"))
		if e == nil {
			var b []byte
			b, e = io.ReadAll(c)
			if e == nil && string(b) == "upload" {
				_, e = c.Write([]byte("response-after-client-EOF"))
			}
		}
		done <- e
	}()
	n, c := trojanNode(t, in, s, 0)
	d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	conn, e := d.DialContext(ctx, netaddrEndpoint(l.Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, len("server-first"))
	if _, e = io.ReadFull(conn, b); e != nil || string(b) != "server-first" {
		t.Fatal("eager request/server-first", e)
	}
	if _, e = conn.Write([]byte("upload")); e != nil {
		t.Fatal(e)
	}
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e = io.ReadAll(conn)
	if e != nil || string(b) != "response-after-client-EOF" {
		t.Fatal("half-close lost response", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestTrojanAuthenticationFloodAndShutdown(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, s := trojanIntent(t)
	prepared, e := (TrojanCompiler{}).Compile(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	h := prepared.(*trojanHandle)
	if e = h.Start(ctx); e != nil {
		t.Fatal(e)
	}
	h.Activate()
	n, c := trojanNode(t, in, s, 0)
	d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	tc := d.(*trojanDialer).tls
	baseline := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 125 {
				raw, e := net.DialTimeout("tcp", netaddr.TCP(n.Endpoint).String(), 2*time.Second)
				if e != nil {
					t.Error(e)
					return
				}
				_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
				if i%5 == 0 {
					_, _ = raw.Write([]byte("not TLS"))
					_ = raw.Close()
					continue
				}
				stream := tls.Client(raw, tc.Clone())
				if e = stream.Handshake(); e != nil {
					t.Error(e)
					_ = raw.Close()
					return
				}
				key := wire.Derive(secret.New("Synthetic-invalid-flood-password"))
				frame, _ := wire.EncodeRequest(key, wire.Connect, access.Endpoint{Host: "127.0.0.1", Port: 1})
				if worker%2 == 0 {
					frame = frame[:20]
				}
				_, _ = stream.Write(frame)
				_ = raw.Close()
			}
		})
	}
	wg.Wait()
	h.mu.Lock()
	peak := len(h.connections)
	h.mu.Unlock()
	if e = h.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	h.mu.Lock()
	end := len(h.connections)
	h.mu.Unlock()
	after, _ := os.ReadDir("/proc/self/fd")
	t.Logf("expected invalid TLS/auth/truncation=1000 unexpected=0 registry_peak_sample=%d registry_end=%d goroutines_start=%d end=%d fd_start=%d end=%d", peak, end, baseline, runtime.NumGoroutine(), len(fds), len(after))
	if end != 0 || h.Stats().Active != 0 || runtime.NumGoroutine() > baseline+2 || len(after) > len(fds) {
		t.Fatal("flood retained resources")
	}
}
func TestTrojanLifecycle25(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, material := trojanIntent(t)
	tcp := netaddrEndpoint(testfixture.TCP(t).Addr())
	udp := trojanUDP(t)
	baseline := runtime.NumGoroutine()
	for i := range 25 {
		prepared, e := (TrojanCompiler{}).Compile(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		h := prepared.(*trojanHandle)
		if h.Start(context.Background()) != nil {
			t.Fatal("start")
		}
		h.Activate()
		n, c := trojanNode(t, in, material, 0)
		d, e := (TrojanOutboundFactory{}).Build(ctx, n, c)
		if e != nil {
			t.Fatal(e)
		}
		trojanTransfer(t, d, tcp, udp)
		_ = d.Close()
		if e = h.Close(context.Background()); e != nil {
			t.Fatal(e)
		}
		h.mu.Lock()
		retained := len(h.connections)
		h.mu.Unlock()
		if retained != 0 || h.Stats().Active != 0 {
			t.Fatal("stopped state retained owners")
		}
		t.Logf("cycle=%d stopped goroutines=%d tcp=%d udp=%d associations=%d listeners=0", i+1, runtime.NumGoroutine(), h.Stats().TCPActive, h.Stats().UDPActive, retained)
	}
	if end := runtime.NumGoroutine(); end > baseline+4 {
		t.Fatal("goroutine retention", baseline, end)
	}
}
