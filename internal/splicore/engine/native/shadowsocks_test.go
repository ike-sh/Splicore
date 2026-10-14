package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func shadowsocksIntent(t *testing.T, method string, multi bool) ports.RuntimeIntent {
	t.Helper()
	in := mieruIntent(t, "tcp")
	return shadowsocksIntentFrom(t, method, multi, in)
}

func shadowsocksIntentFrom(t *testing.T, method string, multi bool, in ports.RuntimeIntent) ports.RuntimeIntent {
	t.Helper()
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
	for _, listener := range in.Inbound.Listeners {
		if listener.Transport == "udp" && listener.Endpoint != n.Endpoint {
			n.Endpoint = listener.Endpoint
			packet, e := (ShadowsocksOutboundFactory{}).Build(underlay.WithFactory(context.Background(), underlay.New()), n, c)
			if e != nil {
				d.Close()
				t.Fatal(e)
			}
			return &shadowsocksFixtureClient{tcp: d, udp: packet}
		}
	}
	return d
}

// Both paths use real native Shadowsocks clients and the same server runtime.
// Its independently owned :0 sockets can have different actual addresses.
type shadowsocksFixtureClient struct{ tcp, udp ports.ClientDialer }

func (d *shadowsocksFixtureClient) DialContext(ctx context.Context, dst access.Endpoint) (net.Conn, error) {
	return d.tcp.DialContext(ctx, dst)
}
func (d *shadowsocksFixtureClient) ListenPacket(ctx context.Context, dst access.Endpoint) (net.PacketConn, error) {
	return d.udp.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
}
func (d *shadowsocksFixtureClient) Close() error {
	return errors.Join(d.tcp.Close(), d.udp.Close())
}

func startShadowsocksFixture(ctx context.Context, h *shadowsocksHandle, in *ports.RuntimeIntent) error {
	h.endpoint = access.Endpoint{Host: "127.0.0.1"}
	if e := h.Start(ctx); e != nil {
		return e
	}
	for n := range in.Inbound.Listeners {
		addr := h.listener.Addr()
		if in.Inbound.Listeners[n].Transport == "udp" {
			addr = h.packet.LocalAddr()
		}
		in.Inbound.Listeners[n].Endpoint = netaddrEndpoint(addr)
	}
	return nil
}
func shadowsocksUDPFixture(t *testing.T) access.Endpoint {
	return shadowsocksUDPFixtureAt(t, "127.0.0.1")
}
func shadowsocksUDPFixtureAt(t *testing.T, host string) access.Endpoint {
	t.Helper()
	requested := net.JoinHostPort(host, "0")
	p, e := net.ListenPacket("udp", requested)
	if e != nil {
		t.Fatal(e)
	}
	actual := p.LocalAddr().String()
	t.Logf("udp_fixture test=%s requested=%s actual=%s created=%s", t.Name(), requested, actual, time.Now().UTC().Format(time.RFC3339Nano))
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
	t.Cleanup(func() {
		p.Close()
		<-done
		t.Logf("udp_fixture test=%s actual=%s closed=%s reader_joined=1", t.Name(), actual, time.Now().UTC().Format(time.RFC3339Nano))
	})
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
				target := mieruTCPFixture(t)
				tcp := netaddrEndpoint(target.Addr())
				in := shadowsocksIntentFrom(t, m.Name, multi, testfixture.MieruIntentAt(t, "tcp", tcp))
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
				if e = startShadowsocksFixture(ctx, h, &in); e != nil {
					t.Fatal(e)
				}
				h.Activate()
				t.Logf("shadowsocks_matrix_bind tcp=%s udp=%s atomic_port0=true", h.listener.Addr(), h.packet.LocalAddr())
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
	compiler := NewShadowsocksCompiler()
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := mieruTCPFixture(t)
	tcp := access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}
	in := shadowsocksIntentFrom(t, "2022-blake3-aes-128-gcm", true, testfixture.MieruIntentAt(t, "tcp", tcp))
	udp := shadowsocksUDPFixture(t)
	baseline := runtime.NumGoroutine()
	peak := baseline
	for cycle := range 25 {
		prepared, e := compiler.Compile(ctx, in)
		if e != nil {
			t.Fatal(e)
		}
		h := prepared.(*shadowsocksHandle)
		// Keep the canonical configuration for the next Compile; actual client
		// endpoint addresses belong only to this cycle's runtime view.
		cycleIntent := in
		cycleIntent.Inbound.Listeners = append([]access.Listener(nil), in.Inbound.Listeners...)
		if e = startShadowsocksFixture(ctx, h, &cycleIntent); e != nil {
			t.Fatal(e)
		}
		h.Activate()
		d := shadowsocksClient(t, cycleIntent, cycle%2)
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
			targetDone := make(chan error, 1)
			targetJoined := make(chan struct{})
			t.Cleanup(func() {
				l.Close()
				select {
				case <-targetJoined:
				case <-time.After(5 * time.Second):
					t.Fatal("half-close target owner did not join")
				}
				t.Logf("half_close_target actual=%s closed=true worker_joined=true", l.Addr())
			})
			go func() {
				defer close(targetJoined)
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
			// Metadata uses an already-owned target endpoint. The real proxy
			// binds :0 itself below; no numeric port is probed or handed off.
			in := shadowsocksIntentFrom(t, method, false, testfixture.MieruIntentAt(t, "tcp", netaddrEndpoint(l.Addr())))
			compiler := NewShadowsocksCompiler()
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			prepared, e := compiler.Compile(ctx, in)
			if e != nil {
				t.Fatal(e)
			}
			h := prepared.(*shadowsocksHandle)
			defer func() {
				if e := h.Close(context.Background()); e != nil {
					t.Fatal(e)
				}
				h.mu.Lock()
				connections, sessions := len(h.connections), len(h.sessions)
				h.mu.Unlock()
				if h.Stats().TCPActive != 0 || h.Stats().UDPActive != 0 || connections != 0 || sessions != 0 {
					t.Fatal("half-close runtime retained sessions")
				}
				t.Logf("half_close_proxy closed=true owners_joined=true TCP=0 UDP=0")
			}()
			// Existing internal test startup pattern: production Start owns
			// the actual OS-assigned sockets for the complete runtime lifetime.
			if e = startShadowsocksFixture(ctx, h, &in); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			t.Logf("half_close_bind tcp=%s udp=%s target=%s atomic_port0=true", h.listener.Addr(), h.packet.LocalAddr(), l.Addr())
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
			<-targetJoined
			t.Log("half_close_payload upload=synthetic-half-close download=after-EOF:synthetic-half-close CloseWrite=PASS EOF=PASS integrity=PASS")
		})
	}
}

func TestShadowsocksUDPMultipleDestinationsOneAssociation(t *testing.T) {
	for _, m := range ss.Methods() {
		t.Run(m.Name, func(t *testing.T) {
			a, b := shadowsocksUDPFixture(t), shadowsocksUDPFixture(t)
			in := shadowsocksIntentFrom(t, m.Name, m.Identity, testfixture.MieruIntentAt(t, "tcp", a))
			ctx := underlay.WithFactory(context.Background(), underlay.New())
			prepared, e := NewShadowsocksCompiler().Compile(ctx, in)
			if e != nil {
				t.Fatal(e)
			}
			h := prepared.(*shadowsocksHandle)
			defer h.Close(context.Background())
			if e = startShadowsocksFixture(ctx, h, &in); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			d := shadowsocksClient(t, in, 0)
			defer d.Close()
			ipv6 := shadowsocksUDPFixtureAt(t, "::1")
			// One real dual-stack socket reserves both families atomically for
			// localhost, which can resolve to either loopback address. Numeric
			// IPv4 and IPv6 destinations each own independent ephemeral sockets.
			domain := shadowsocksUDPFixtureAt(t, "::")
			domain.Host = "localhost"
			p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, a)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			p.SetDeadline(time.Now().Add(5 * time.Second))
			for _, dst := range []access.Endpoint{a, b, ipv6, domain, a} {
				payload := []byte("same-association " + dst.Host)
				if _, e = p.WriteTo(payload, netaddr.UDP(access.Endpoint{Host: dst.Host, Port: dst.Port})); e != nil {
					t.Fatal(e)
				}
				buffer := make([]byte, 4096)
				n, reply, e := p.ReadFrom(buffer)
				if e != nil || !bytes.Equal(buffer[:n], payload) {
					t.Fatal("multiple destination integrity", e)
				}
				endpoint, e := netaddr.From(reply)
				if e != nil || endpoint.Port != dst.Port || dst.Host != "localhost" && endpoint.Host != dst.Host || dst.Host == "localhost" && !net.ParseIP(endpoint.Host).IsLoopback() {
					t.Fatal("destination address/family", dst, endpoint, e)
				}
				t.Logf("udp_destination target=%s reply=%s payload_integrity=PASS", netaddr.UDP(dst), reply)
			}
			if h.Stats().UDPSessions != 4 || h.BindingStats(in.Bindings[0].ID).UDPSessions != 4 {
				t.Fatal("association/account attribution")
			}
		})
	}
}

func TestShadowsocksUDPEphemeralFixtureWithOccupiedOtherFamily(t *testing.T) {
	owner, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	port := owner.LocalAddr().(*net.UDPAddr).Port
	ipv4, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ipv4.Close()
	// Keep independent IPv4 and IPv6 owners live. The new IPv6 fixture must
	// allocate its own port; it cannot borrow either owner's numeric port.
	duplicate, err := net.ListenPacket("udp", owner.LocalAddr().String())
	if duplicate != nil {
		duplicate.Close()
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatal("known IPv6 owner did not exclude duplicate bind", err)
	}
	fresh := shadowsocksUDPFixtureAt(t, "::1")
	if int(fresh.Port) == port {
		t.Fatal("fresh IPv6 fixture reused occupied IPv6 port")
	}
	t.Logf("udp_known_owner owner=%s ipv4=%s fresh=%s legacy_collision=EADDRINUSE", owner.LocalAddr(), ipv4.LocalAddr(), netaddr.UDP(fresh))
	dual := shadowsocksUDPFixtureAt(t, "::")
	for _, dst := range []access.Endpoint{fresh, {Host: "127.0.0.1", Port: dual.Port}, {Host: "::1", Port: dual.Port}} {
		conn, err := net.Dial("udp", netaddr.UDP(dst).String())
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := []byte("owned-UDP-" + dst.Host)
		if _, err = conn.Write(payload); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		n, err := conn.Read(got)
		conn.Close()
		if err != nil || !bytes.Equal(got[:n], payload) {
			t.Fatal("ephemeral fixture payload/address family", dst, err)
		}
	}
}
