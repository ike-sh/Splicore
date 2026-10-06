package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func shadowsocksIntent(t *testing.T, method string, multi bool) ports.RuntimeIntent {
	t.Helper()
	in := mieruIntent(t, "tcp")
	m, _ := ss.Lookup(method)
	data, _ := json.Marshal(ss.Settings{Method: method, MultiUser: multi, UDP: true})
	in.Inbound.Name = "synthetic-shadowsocks"
	in.Inbound.Protocol = ss.Key(m.Edition)
	in.Inbound.Settings.Data = data
	l := in.Inbound.Listeners[0]
	l.ID, _ = identity.NewID()
	l.Transport = "udp"
	in.Inbound.Listeners = append(in.Inbound.Listeners, l)
	if m.Edition == "2022" && !multi {
		in.Bindings = in.Bindings[:1]
		in.Credentials = in.Credentials[:1]
	}
	for n := range in.Credentials {
		p, e := ss.Generate(method)
		if e != nil {
			t.Fatal(e)
		}
		in.Credentials[n].Payload = p
		in.Credentials[n].Kind = p.Kind()
	}
	if multi {
		p, e := ss.Generate(method)
		if e != nil {
			t.Fatal(e)
		}
		id, _ := identity.NewID()
		in.ServerCredentials = []access.Credential{{ID: id, OwnerInboundID: &in.Inbound.ID, Kind: access.PSK, Schema: 1, State: "active", Payload: p, Stamp: identity.NewStamp(time.Now())}}
	}
	return in
}
func shadowsocksClient(t *testing.T, in ports.RuntimeIntent, index int) ports.ClientDialer {
	t.Helper()
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	s, _ := ss.Decode(in.Inbound.Settings.Data)
	data, _ := json.Marshal(ss.ClientOptions{Method: s.Method, UDP: true})
	n := client.RemoteNode{ID: id, CredentialID: cid, Name: "synthetic-node", Protocol: in.Inbound.Protocol, Endpoint: in.Inbound.Listeners[0].Endpoint, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: data}}
	c := in.Credentials[index]
	c.ID = cid
	c.OwnerAccountID = nil
	c.OwnerNodeID = &id
	if s.MultiUser {
		c.Payload = access.PSKPayload{Key: secret.New(ss.Material(in.ServerCredentials[0].Payload) + ":" + ss.Material(c.Payload))}
	}
	d, e := (ShadowsocksOutboundFactory{}).Build(underlay.WithFactory(context.Background(), underlay.New()), n, c)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func shadowsocksUDPFixture(t *testing.T) access.Endpoint {
	return shadowsocksUDPFixtureAt(t, "127.0.0.1", 0)
}
func shadowsocksUDPFixtureAt(t *testing.T, host string, port uint16) access.Endpoint {
	t.Helper()
	p, e := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
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
			p.WriteTo(b[:n], a)
		}
	}()
	t.Cleanup(func() { p.Close(); <-done })
	return access.Endpoint{Host: host, Port: uint16(p.LocalAddr().(*net.UDPAddr).Port)}
}
func shadowsocksTraffic(d ports.ClientDialer, tcp, udp access.Endpoint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := d.DialContext(ctx, tcp)
	if e != nil {
		return e
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("synthetic-SS-frame-"), 4096)
	if _, e = c.Write(payload); e != nil {
		return e
	}
	b := make([]byte, len(payload))
	if _, e = io.ReadFull(c, b); e != nil {
		return e
	}
	if !bytes.Equal(b, payload) {
		return io.ErrUnexpectedEOF
	}
	p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
	if e != nil {
		return e
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(5 * time.Second))
	for _, payload := range [][]byte{[]byte("synthetic-UDP"), nil, bytes.Repeat([]byte("u"), 32000)} {
		if _, e = p.WriteTo(payload, nil); e != nil {
			return e
		}
		n, _, e := p.ReadFrom(b)
		if e != nil {
			return fmt.Errorf("UDP size %d: %w", len(payload), e)
		}
		if !bytes.Equal(b[:n], payload) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}
func TestShadowsocksNativeTCPUDPMatrix(t *testing.T) {
	for _, m := range ss.Methods() {
		for _, multi := range []bool{false, true} {
			if multi && !m.Identity {
				continue
			}
			name := m.Name
			if multi {
				name += "/multi"
			}
			t.Run(name, func(t *testing.T) {
				in := shadowsocksIntent(t, m.Name, multi)
				compiler := NewShadowsocksCompiler()
				ctx := underlay.WithFactory(context.Background(), underlay.New())
				prepared, e := compiler.Compile(ctx, in)
				if e != nil {
					t.Fatal(e)
				}
				h := prepared.(*shadowsocksHandle)
				defer func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if e := h.Close(ctx); e != nil {
						t.Error(e)
					}
				}()
				if e = h.Start(ctx); e != nil {
					t.Fatal(e)
				}
				h.Activate()
				target := mieruTCPFixture(t)
				tcp := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
				udp := shadowsocksUDPFixture(t)
				for n := range in.Bindings {
					d := shadowsocksClient(t, in, n)
					if e = shadowsocksTraffic(d, tcp, udp); e != nil {
						d.Close()
						t.Fatal(e)
					}
					d.Close()
					if stats := h.BindingStats(in.Bindings[n].ID); stats.Upload == 0 || stats.Download == 0 {
						t.Fatal("missing attributed stats")
					}
					for _, untouched := range in.Bindings[n+1:] {
						if stats := h.BindingStats(untouched.ID); stats.Upload != 0 || stats.Download != 0 || stats.Sessions != 0 {
							t.Fatal("authenticated traffic was attributed to another user")
						}
					}
				}
			})
		}
	}
}
func TestShadowsocksLifecycle25(t *testing.T) {
	in := shadowsocksIntent(t, "2022-blake3-aes-128-gcm", true)
	compiler := NewShadowsocksCompiler()
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := mieruTCPFixture(t)
	tcp := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
	udp := shadowsocksUDPFixture(t)
	baseline := runtime.NumGoroutine()
	peak := baseline
	for cycle := range 25 {
		prepared, e := compiler.Compile(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		h := prepared.(*shadowsocksHandle)
		if e = h.Start(ctx); e != nil {
			t.Fatal(e)
		}
		h.Activate()
		d := shadowsocksClient(t, in, cycle%2)
		if e = shadowsocksTraffic(d, tcp, udp); e != nil {
			t.Fatal(e)
		}
		peak = max(peak, runtime.NumGoroutine())
		// Race close with active client Read/Write and raw handshake admission.
		c, e := d.DialContext(ctx, tcp)
		if e != nil {
			t.Fatal(e)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = c.Read(make([]byte, 64)) }()
		go func() { defer wg.Done(); _, _ = c.Write([]byte("shutdown")) }()
		d.Close()
		timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
		e = h.Close(timeout)
		cancel()
		wg.Wait()
		if e != nil {
			t.Fatal(e)
		}
		if stats := h.Stats(); stats.Active != 0 {
			t.Fatal("server active session leak", stats)
		}
		h.mu.Lock()
		count := len(h.connections) + len(h.sessions)
		h.mu.Unlock()
		if count != 0 {
			t.Fatal("owned connection leak")
		}
		t.Logf("cycle=%d stopped_goroutines=%d listeners=0 TCP=0 UDP=0", cycle+1, runtime.NumGoroutine())
	}
	t.Logf("start=%d peak=%d end=%d", baseline, peak, runtime.NumGoroutine())
	if runtime.NumGoroutine() > baseline+3 {
		t.Fatal("stopped goroutine growth")
	}
}

func TestShadowsocksTCPHalfClose(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			targetDone := make(chan error, 1)
			go func() {
				raw, e := l.Accept()
				if e != nil {
					targetDone <- e
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				b, e := io.ReadAll(raw)
				if e == nil {
					_, e = raw.Write(append([]byte("after-EOF:"), b...))
				}
				targetDone <- e
			}()
			in := shadowsocksIntent(t, method, false)
			compiler := NewShadowsocksCompiler()
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			prepared, e := compiler.Compile(ctx, in)
			if e != nil {
				t.Fatal(e)
			}
			h := prepared.(*shadowsocksHandle)
			defer h.Close(context.Background())
			if e = h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			d := shadowsocksClient(t, in, 0)
			defer d.Close()
			c, e := d.DialContext(ctx, access.Endpoint{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port)})
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, e = c.Write([]byte("synthetic-half-close")); e != nil {
				t.Fatal(e)
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(c)
			if e != nil || string(body) != "after-EOF:synthetic-half-close" {
				t.Fatal("response after client EOF", string(body), e)
			}
			if e = <-targetDone; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestShadowsocksUDPMultipleDestinationsOneAssociation(t *testing.T) {
	for _, m := range ss.Methods() {
		t.Run(m.Name, func(t *testing.T) {
			in := shadowsocksIntent(t, m.Name, m.Identity)
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			prepared, e := NewShadowsocksCompiler().Compile(ctx, in)
			if e != nil {
				t.Fatal(e)
			}
			h := prepared.(*shadowsocksHandle)
			defer h.Close(context.Background())
			if e = h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			d := shadowsocksClient(t, in, 0)
			defer d.Close()
			a, b := shadowsocksUDPFixture(t), shadowsocksUDPFixture(t)
			shadowsocksUDPFixtureAt(t, "::1", b.Port)
			p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, a)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			p.SetDeadline(time.Now().Add(5 * time.Second))
			domain := b
			domain.Host = "localhost"
			for _, dst := range []access.Endpoint{a, b, domain, a} {
				payload := []byte("same-association " + dst.Host)
				if _, e = p.WriteTo(payload, netaddr.UDP(access.Endpoint{Host: dst.Host, Port: dst.Port})); e != nil {
					t.Fatal(e)
				}
				buffer := make([]byte, 4096)
				n, _, e := p.ReadFrom(buffer)
				if e != nil || !bytes.Equal(buffer[:n], payload) {
					t.Fatal("multiple destination integrity", e)
				}
			}
			if h.Stats().UDPSessions != 3 || h.BindingStats(in.Bindings[0].ID).UDPSessions != 3 {
				t.Fatal("association/account attribution")
			}
		})
	}
}
