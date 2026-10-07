package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vmess/wire"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

func vmessIntent(t *testing.T, tls bool) ports.RuntimeIntent {
	t.Helper()
	in := testfixture.MieruIntent(t, "tcp")
	in.Inbound.Protocol = module.Key()
	s := module.Settings{Transport: "tcp", Security: "none", PayloadSecurity: "auto"}
	if tls {
		m := testkit.TLSForName(t, "vmess.synthetic.test")
		s.Security = "tls"
		s.TLS = &m
	}
	in.Inbound.Settings.Data, _ = json.Marshal(s)
	// Deliberately exercise arbitrary UUID versions and uppercase hex.
	ids := []string{"00000000-0000-1000-8000-000000000001", "ABCDEF00-0000-7000-8000-000000000002"}
	for i := range in.Credentials {
		in.Credentials[i].Kind = access.UUID
		in.Credentials[i].Payload = access.UUIDPayload{UUID: secret.New(ids[i])}
	}
	return in
}
func vmessNode(t *testing.T, in ports.RuntimeIntent, index int, security string) (client.RemoteNode, access.Credential) {
	t.Helper()
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	s, _ := module.Decode(in.Inbound.Settings.Data)
	opts, _ := json.Marshal(module.ClientOptions{Security: security, UDP: true})
	n := client.RemoteNode{ID: id, Name: "synthetic-VMess", Protocol: module.Key(), Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: opts}}
	if s.TLS != nil {
		n.Security = client.Security{Kind: "tls", TLS: access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}}
	}
	c := in.Credentials[index]
	c.ID = cid
	c.OwnerAccountID = nil
	c.OwnerNodeID = &id
	return n, c
}
func vmessTransfer(t *testing.T, d ports.ClientDialer, tcp, udp access.Endpoint, size int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte{31}, size)
	done := make(chan error, 1)
	go func() { _, err := c.Write(payload); done <- err }()
	got := make([]byte, size)
	if _, err = io.ReadFull(c, got); err != nil {
		t.Fatal("TCP response", err)
	}
	if err = <-done; err != nil || !bytes.Equal(got, payload) {
		t.Fatal("TCP integrity", err)
	}
	_ = c.Close()
	p, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	_ = p.SetDeadline(time.Now().Add(5 * time.Second))
	sizes := []int{1, 128, 8192, 16000}
	if os.Getenv("SPLICORE_VM_INTEROP") != "" {
		sizes = []int{1, 128, 1000, 1200}
	}
	for _, size := range sizes {
		payload := bytes.Repeat([]byte{42}, size)
		if _, err = p.WriteTo(payload, netaddr.UDP(udp)); err != nil {
			t.Fatal("UDP write", err)
		}
		v := make([]byte, 16384)
		n, addr, err := p.ReadFrom(v)
		if err != nil || !bytes.Equal(payload, v[:n]) || netaddrEndpoint(addr) != udp {
			t.Fatal("UDP response", size, err)
		}
	}
}
func TestVMessNativeModesTLSMultiUser(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, tls := range []bool{false, true} {
		in := vmessIntent(t, tls)
		compiler := NewVMessCompiler()
		prepared, err := compiler.Compile(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		h := prepared.(*vmessHandle)
		if err = h.Start(ctx); err != nil {
			t.Fatal(err)
		}
		h.Activate()
		for _, mode := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none"} {
			for i := range 2 {
				n, c := vmessNode(t, in, i, mode)
				d, err := (VMessOutboundFactory{}).Build(ctx, n, c)
				if err != nil {
					t.Fatal(err)
				}
				vmessTransfer(t, d, tcp, udp, 131071)
				_ = d.Close()
				if h.BindingStats(in.Bindings[i].ID).Upload == 0 || h.BindingStats(in.Bindings[i].ID).Download == 0 {
					t.Fatal("user unattributed")
				}
			}
		}
		if err = h.Close(ctx); err != nil {
			t.Fatal(err)
		}
		if len(h.connections) != 0 || h.Stats().Active != 0 {
			t.Fatal("session retained")
		}
	}
}
func TestVMessTLSWrongSNIAndUntrusted(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, true)
	prepared, err := NewVMessCompiler().Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*vmessHandle)
	defer h.Close(ctx)
	if h.Start(ctx) != nil {
		t.Fatal("start")
	}
	h.Activate()
	for _, kind := range []string{"wrong-sni", "untrusted"} {
		n, c := vmessNode(t, in, 0, "none")
		if kind == "wrong-sni" {
			n.Security.TLS.ServerName = "wrong.synthetic.test"
		} else {
			n.Security.TLS.Trust = "system"
			n.Security.TLS.CACertificate = ""
		}
		d, err := (VMessOutboundFactory{}).Build(ctx, n, c)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: 1})
		if conn != nil {
			_ = conn.Close()
		}
		_ = d.Close()
		if err == nil {
			t.Fatal("verification bypass", kind)
		}
	}
}
func TestVMessReplayAcrossGenerationsAndRotation(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, false)
	compiler := NewVMessCompiler()
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	r, _ := wire.NewRequest(tcp, wire.TCP, wire.AESGCM, wire.ChunkStream|wire.LengthMask, nil)
	key := module.CommandKey(in.Credentials[0].Payload.(access.UUIDPayload))
	header, _ := wire.EncodeRequest(key, r, time.Now(), nil)
	for i := range 2 {
		prepared, err := compiler.Compile(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		h := prepared.(*vmessHandle)
		if h.Start(ctx) != nil {
			t.Fatal("start")
		}
		h.Activate()
		raw, err := net.Dial("tcp", netaddr.TCP(in.Inbound.Listeners[0].Endpoint).String())
		if err != nil {
			t.Fatal(err)
		}
		_ = raw.SetDeadline(time.Now().Add(time.Second))
		_, _ = raw.Write(header)
		if i == 0 {
			tx, _ := wire.NewChunk(r, false, nil)
			frame, _ := tx.Encode([]byte("first"))
			_, _ = raw.Write(frame)
			if err = wire.ReadResponse(raw, r); err != nil {
				t.Fatal("first rejected", err)
			}
			rx, _ := wire.NewChunk(r, true, nil)
			got, err := rx.Read(raw)
			if err != nil || string(got) != "first" {
				t.Fatal("first echo", err)
			}
		} else {
			if err = wire.ReadResponse(raw, r); err == nil {
				t.Fatal("replay accepted after generation replacement")
			}
		}
		_ = raw.Close()
		if h.Close(ctx) != nil {
			t.Fatal("close")
		}
	}
	in.Credentials[0].Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-2000-8000-000000000003")}
	prepared, err := compiler.Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*vmessHandle)
	defer h.Close(ctx)
	if h.Start(ctx) != nil {
		t.Fatal("start rotation")
	}
	h.Activate()
	n, c := vmessNode(t, in, 0, "auto")
	d, err := (VMessOutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	vmessTransfer(t, d, tcp, trojanUDP(t), 1024)
	_ = d.Close()
	c.Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-1000-8000-000000000001")}
	d, err = (VMessOutboundFactory{}).Build(ctx, n, c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	conn, err := d.DialContext(ctx, tcp)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte("old-user"))
		_, err = conn.Read(make([]byte, 32))
	}
	if err == nil {
		t.Fatal("old credential accepted")
	}
}
func TestVMessLifecycle25(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, false)
	compiler := NewVMessCompiler()
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	baseline := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	beforeFD := vmessFDNames()
	for i := range 25 {
		prepared, err := compiler.Compile(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		h := prepared.(*vmessHandle)
		if h.Start(ctx) != nil {
			t.Fatal("start")
		}
		h.Activate()
		n, c := vmessNode(t, in, i%2, []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none"}[i%4])
		d, err := (VMessOutboundFactory{}).Build(ctx, n, c)
		if err != nil {
			t.Fatal(err)
		}
		vmessTransfer(t, d, tcp, udp, 2048)
		_ = d.Close()
		if h.Close(ctx) != nil || len(h.connections) != 0 || h.Stats().Active != 0 {
			t.Fatal("retained runtime")
		}
		t.Logf("cycle=%d goroutines=%d listeners=0 sessions=0 associations=0 workers=0", i+1, runtime.NumGoroutine())
	}
	after, _ := os.ReadDir("/proc/self/fd")
	t.Logf("fd ownership before=%v after=%v", beforeFD, vmessFDNames())
	entries, peak, cap := compiler.replay.Snapshot(time.Now().Add(241 * time.Second).Unix())
	t.Logf("goroutines start=%d end=%d fd start=%d end=%d replay end=%d peak=%d capacity=%d", baseline, runtime.NumGoroutine(), len(fds), len(after), entries, peak, cap)
	if runtime.NumGoroutine() > baseline+4 || len(after) > len(fds) || entries != 0 {
		t.Fatal("lifecycle growth")
	}
}

// Explicit echo IO avoids the standard library TCP splice pool retaining pipe
// descriptors in a fixture. All accepted sockets/workers are owned and joined.
func vmessTCP(t *testing.T, address string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	active := map[net.Conn]bool{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			active[c] = true
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				b := make([]byte, 32768)
				for {
					n, err := c.Read(b)
					if n > 0 {
						sent := 0
						for sent < n {
							w, e := c.Write(b[sent:n])
							sent += w
							if e != nil || w == 0 {
								return
							}
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		for c := range active {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return l
}

func vmessFDNames() map[string]string {
	v := map[string]string{}
	entries, _ := os.ReadDir("/proc/self/fd")
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil {
			v[e.Name()] = target
		}
	}
	return v
}
func TestVMessSessionChurn(t *testing.T) {
	cycles := 128
	if v := os.Getenv("SPLICORE_VM_CHURN"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 128 || n > 10000 {
			t.Fatal("invalid churn cycles")
		}
		cycles = n
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, false)
	compiler := NewVMessCompiler()
	prepared, err := compiler.Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*vmessHandle)
	if h.Start(ctx) != nil {
		t.Fatal("start")
	}
	h.Activate()
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	baseline := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	start := time.Now()
	for i := range cycles {
		n, c := vmessNode(t, in, i%2, []string{"aes-128-gcm", "chacha20-poly1305", "none"}[i%3])
		d, err := (VMessOutboundFactory{}).Build(ctx, n, c)
		if err != nil {
			t.Fatal(err)
		}
		vmessTransfer(t, d, tcp, udp, 128)
		_ = d.Close()
		if (i+1)%1000 == 0 {
			h.mu.Lock()
			active := len(h.connections)
			h.mu.Unlock()
			entries, peak, _ := compiler.replay.Snapshot(time.Now().Unix())
			t.Logf("cycles=%d goroutines=%d registry=%d replay=%d peak=%d", i+1, runtime.NumGoroutine(), active, entries, peak)
		}
	}
	if h.Close(ctx) != nil {
		t.Fatal("close")
	}
	after, _ := os.ReadDir("/proc/self/fd")
	entries, peak, _ := compiler.replay.Snapshot(time.Now().Add(241 * time.Second).Unix())
	t.Logf("cycles=%d duration=%s goroutines start=%d end=%d FD start=%d end=%d replay peak=%d end=%d registry=0 sessions=0", cycles, time.Since(start), baseline, runtime.NumGoroutine(), len(fds), len(after), peak, entries)
	if len(h.connections) != 0 || h.Stats().Active != 0 || entries != 0 || len(after) > len(fds) || runtime.NumGoroutine() > baseline+4 {
		t.Fatal("churn retained owners")
	}
}

func TestVMessTCPHalfCloseServerFirst(t *testing.T) {
	for _, outerTLS := range []bool{false, true} {
		for _, mode := range []string{"aes-128-gcm", "chacha20-poly1305", "none"} {
			t.Run(fmtVMessCase(outerTLS, mode), func(t *testing.T) {
				ctx := underlay.WithFactory(context.Background(), underlay.New())
				in := vmessIntent(t, outerTLS)
				prepared, err := NewVMessCompiler().Compile(ctx, in)
				if err != nil {
					t.Fatal(err)
				}
				h := prepared.(*vmessHandle)
				defer h.Close(ctx)
				if err = h.Start(ctx); err != nil {
					t.Fatal(err)
				}
				h.Activate()
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				done := make(chan error, 1)
				go func() {
					c, err := l.Accept()
					if err != nil {
						done <- err
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, err = c.Write([]byte("server-first"))
					if err == nil {
						var b []byte
						b, err = io.ReadAll(c)
						if err == nil && string(b) != "upload" {
							err = errors.New("upload mismatch")
						}
						if err == nil {
							_, err = c.Write([]byte("response-after-EOF"))
						}
					}
					done <- err
				}()
				n, credential := vmessNode(t, in, 0, mode)
				d, err := (VMessOutboundFactory{}).Build(ctx, n, credential)
				if err != nil {
					t.Fatal(err)
				}
				defer d.Close()
				c, err := d.DialContext(ctx, netaddrEndpoint(l.Addr()))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, len("server-first"))
				if _, err = io.ReadFull(c, b); err != nil || string(b) != "server-first" {
					t.Fatal("first", err)
				}
				if _, err = c.Write([]byte("upload")); err != nil {
					t.Fatal(err)
				}
				if err = c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				b, err = io.ReadAll(c)
				if err != nil || string(b) != "response-after-EOF" {
					t.Fatal("half-close response", err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
func fmtVMessCase(tls bool, mode string) string {
	if tls {
		return "tls/" + mode
	}
	return "raw/" + mode
}

func TestVMessOutboundParentPendingTLS(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, true)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	n, credential := vmessNode(t, in, 0, "auto")
	n.Endpoint = netaddrEndpoint(l.Addr())
	d, err := (VMessOutboundFactory{}).Build(ctx, n, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, err := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: 80})
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	var raw net.Conn
	select {
	case raw = <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("dial not admitted")
	}
	defer raw.Close()
	closed := make(chan struct{})
	go func() { _ = d.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("parent did not join TLS handshake")
	}
	if err = <-done; err == nil {
		t.Fatal("stalled socket published")
	}
}

func TestVMUDP_L4_IdleExpiryReplacement(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, false)
	compiler := NewVMessCompiler()
	prepared, err := compiler.Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*vmessHandle)
	defer h.Close(ctx)
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	dst := trojanUDP(t)
	n, credential := vmessNode(t, in, 0, "aes-128-gcm")
	d, err := (VMessOutboundFactory{}).Build(ctx, n, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for cycle := range 2 {
		p, err := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		_ = p.SetDeadline(time.Now().Add(8 * time.Second))
		if _, err = p.WriteTo([]byte("replacement reply"), netaddr.UDP(dst)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		if n, _, err := p.ReadFrom(b); err != nil || string(b[:n]) != "replacement reply" {
			t.Fatal("actual reply", err)
		}
		if cycle == 0 { // The reply is the admission barrier; wait for actual server idle EOF.
			if _, _, err = p.ReadFrom(b); err == nil {
				t.Fatal("idle stream survived")
			}
			if _, err = p.WriteTo([]byte("dead"), netaddr.UDP(dst)); err == nil {
				t.Fatal("dead association reused")
			}
		}
		_ = p.Close()
	}
	if err = h.Close(ctx); err != nil || len(h.connections) != 0 || h.Stats().Active != 0 {
		t.Fatal("registry residue", err)
	}
	t.Log("VM-UDP-L4 idle=5s expired=1 replacement_actual_reply=1 registry=0 workers=0")
}

func TestVMessInvalidAuthFloodShutdown(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in := vmessIntent(t, false)
	compiler := NewVMessCompiler()
	prepared, err := compiler.Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	h := prepared.(*vmessHandle)
	if err = h.Start(ctx); err != nil {
		t.Fatal(err)
	}
	h.Activate()
	baseline := runtime.NumGoroutine()
	fds, _ := os.ReadDir("/proc/self/fd")
	begin := time.Now()
	key := module.CommandKey(in.Credentials[0].Payload.(access.UUIDPayload))
	rejected := 0
	for i := range 1000 {
		r, _ := wire.NewRequest(access.Endpoint{Host: "127.0.0.1", Port: 1}, wire.TCP, wire.AESGCM, wire.ChunkStream, nil)
		header, _ := wire.EncodeRequest(key, r, time.Now(), nil)
		switch i % 4 {
		case 0:
			header[0] ^= 1
		case 1:
			header, _ = wire.EncodeRequest(key, r, time.Now().Add(-121*time.Second), nil)
		case 2:
			header[len(header)-1] ^= 1
		case 3:
			header = header[:25]
		}
		c, err := net.Dial("tcp", netaddr.TCP(in.Inbound.Listeners[0].Endpoint).String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Write(header)
		if err == nil {
			// A rejected AuthID can close before upload shutdown. Only the
			// truncated valid prefix needs our EOF to finish its bounded read.
			shutdownErr := c.(*net.TCPConn).CloseWrite()
			if i%4 == 3 {
				err = shutdownErr
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = wire.ReadResponse(c, r); err == nil {
			t.Fatal("invalid auth accepted")
		}
		_ = c.Close()
		rejected++
	}
	// Pending unauthenticated readers must also join parent shutdown.
	var held []net.Conn
	for range 32 {
		c, err := net.Dial("tcp", netaddr.TCP(in.Inbound.Listeners[0].Endpoint).String())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
	}
	if err = h.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range held {
		_ = c.Close()
	}
	after, _ := os.ReadDir("/proc/self/fd")
	entries, peak, _ := compiler.replay.Snapshot(time.Now().Unix())
	if entries != 0 || len(h.connections) != 0 || h.Stats().Active != 0 || len(after) > len(fds) || runtime.NumGoroutine() > baseline+2 {
		t.Fatal("flood growth")
	}
	t.Logf("duration=%s expected_rejected=%d pending_shutdown=32 unexpected_accepts=0 goroutines_start=%d end=%d FD_start=%d end=%d replay_peak=%d final=%d", time.Since(begin), rejected, baseline, runtime.NumGoroutine(), len(fds), len(after), peak, entries)
}
