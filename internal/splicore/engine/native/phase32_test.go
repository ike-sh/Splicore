//go:build with_quic && with_utls

package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func phase32Enable(t *testing.T, in *ports.RuntimeIntent) string {
	return phase32EnableMode(t, in, "random")
}

func phase32EnableMode(t *testing.T, in *ports.RuntimeIntent, mode string) string {
	t.Helper()
	padding := os.Getenv("SPLICORE_PHASE32_TEST_PADDING")
	if padding == "" {
		padding = "100-35-35"
	}
	decryption, client, e := encryption.Generate("mlkem768", mode, "0rtt", "600s", padding)
	if e != nil {
		t.Fatal(e)
	}
	var s vl.Settings
	if e = json.Unmarshal(in.Inbound.Settings.Data, &s); e != nil {
		t.Fatal(e)
	}
	s.Encryption = client
	in.Inbound.Settings.Data, _ = json.Marshal(s)
	cred := in.Credentials[0]
	cred.OwnerAccountID = nil
	cred.OwnerInboundID = &in.Inbound.ID
	cred.Kind = access.PrivateKey
	cred.Payload = access.PrivateKeyPayload{Algorithm: "vless-encryption", Material: secret.New(decryption)}
	in.ServerCredentials = append(in.ServerCredentials, cred)
	return client
}

func TestPhase32NativeTransportsRestartAndUDP(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, kind := range []string{"tcp", "xhttp-h1", "xhttp-h2", "mkcp", "http", "h2", "quic-stream"} {
		t.Run(kind, func(t *testing.T) {
			in, n, c := sharedIntent(t, "vless", "h2", true)
			transport := cfg.Config{Kind: kind, Path: "/encrypted", Host: "core.synthetic.test"}
			if kind == "quic-stream" || kind == "tcp" {
				transport.Path = ""
				transport.Host = ""
			}
			if kind == "xhttp-h1" || kind == "xhttp-h2" {
				transport.Kind = "xhttp"
				transport.XHTTP = &cfg.XHTTP{Mode: "packet-up"}
				n.Security.TLS.ALPN = []string{"http/1.1"}
				if kind == "xhttp-h2" {
					n.Security.TLS.ALPN = []string{"h2"}
				}
			}
			if kind == "mkcp" {
				transport = cfg.Config{Kind: "mkcp"}
			}
			var s vl.Settings
			_ = json.Unmarshal(in.Inbound.Settings.Data, &s)
			s.Stream = &transport
			in.Inbound.Settings.Data, _ = json.Marshal(s)
			for j := range in.Inbound.Listeners {
				in.Inbound.Listeners[j].Transport = transport.Carrier()
			}
			n.Transport = transport
			client := phase32Enable(t, &in)
			cc, err := encryption.ParseClient(client)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := encryption.NewClient(cc)
			if err != nil {
				t.Fatal(err)
			}
			// This helper opens TCP and UDP sessions under one caller context.
			// Cover both admissions and retain the existing application budget.
			budget := 2*encrypted.HandshakeTimeout() + 5*time.Second
			n.Options.Data, _ = json.Marshal(vl.ClientOptions{Encryption: client, Security: s.Security, Flow: s.Flow, PacketEncoding: s.PacketEncoding})
			for range 2 {
				h, endpoint := startMKCP(t, ctx, "vless", in, "127.0.0.1")
				n.Endpoint = endpoint
				d := sharedBuild(t, ctx, n, c)
				sharedPayloadBudget(t, d, tcp, udp, budget)
				sharedPayloadBudget(t, d, tcp, udp, budget)
				d.Close()
				if e := h.Close(ctx); e != nil {
					t.Fatal(e)
				}
				if h.Stats().Active != 0 {
					t.Fatal("orphan session")
				}
			}
		})
	}
}

func TestPhase32UUIDRejectionAndHalfClose(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, n, c := sharedIntent(t, "vless", "ws", false)
	n.Transport = cfg.Config{Kind: "tcp"}
	var s vl.Settings
	_ = json.Unmarshal(in.Inbound.Settings.Data, &s)
	s.Stream = &n.Transport
	in.Inbound.Settings.Data, _ = json.Marshal(s)
	client := phase32Enable(t, &in)
	decoded, err := vl.Decode(in.Inbound.Settings.Data)
	if err != nil {
		t.Fatal("settings decode", err)
	}
	if err = (vl.Module{Security: vl.Plain}).ValidateInbound(in.Inbound); err != nil {
		t.Fatal("inbound validate", err)
	}
	if _, err = vl.DecryptionConfig(decoded, in.ServerCredentials); err != nil {
		t.Fatal("decryption validate", err)
	}
	if _, err = (vl.Module{Security: vl.Plain}).BuildRuntime(ctx, in); err != nil {
		t.Fatal("runtime validate", err)
	}
	n.Options.Data, _ = json.Marshal(vl.ClientOptions{Encryption: client, Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp"})
	h, ep := startMKCP(t, ctx, "vless", in, "127.0.0.1")
	defer h.Close(ctx)
	n.Endpoint = ep
	target, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	reached := make(chan bool, 2)
	go func() {
		for {
			conn, e := target.Accept()
			if e != nil {
				return
			}
			reached <- true
			go func() { defer conn.Close(); b, _ := io.ReadAll(conn); _, _ = conn.Write(append(b, []byte("reply")...)) }()
		}
	}()
	d := sharedBuild(t, ctx, n, c)
	defer d.Close()
	conn, e := d.DialContext(ctx, netaddrEndpoint(target.Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = conn.Write([]byte("half"))
	if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(conn)
	if e != nil || string(b) != "halfreply" {
		t.Fatal("half close", e)
	}
	<-reached
	c.Payload = access.UUIDPayload{UUID: secret.New("78123211-1234-4567-8912-123456789123")}
	bad := sharedBuild(t, ctx, n, c)
	defer bad.Close()
	conn, e = bad.DialContext(ctx, netaddrEndpoint(target.Addr()))
	if e == nil {
		conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte("unauthorized"))
		_, _ = conn.Read(make([]byte, 1))
		conn.Close()
	}
	select {
	case <-reached:
		t.Fatal("wrong UUID reached outbound")
	default:
	}
	t.Log("outer security none; encrypted UUID auth; half close passed")
}

func TestPhase32UDPDestinationsAndShutdown(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, n, credential := phaseFixture(t, phaseProfile{security: vl.Plain, flow: vl.NoFlow})
	public := phase32Enable(t, &in)
	n.Options.Data, _ = json.Marshal(vl.ClientOptions{Encryption: public, Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp"})
	h, endpoint := startMKCP(t, ctx, "vless", in, "127.0.0.1")
	defer h.Close(ctx)
	n.Endpoint = endpoint
	d := sharedBuild(t, ctx, n, credential)
	defer d.Close()
	ipv4 := trojanUDP(t)
	ipv6, e := net.ListenPacket("udp", "[::]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ipv6.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			count, a, e := ipv6.ReadFrom(b)
			if e != nil {
				return
			}
			_, _ = ipv6.WriteTo(b[:count], a)
		}
	}()
	ipv6Endpoint := netaddrEndpoint(ipv6.LocalAddr())
	ipv6Endpoint.Host = "::1"
	hostname := ipv6Endpoint
	hostname.Host = "localhost"
	for _, dst := range []access.Endpoint{ipv4, ipv6Endpoint, hostname} {
		t.Run(dst.Host, func(t *testing.T) {
			for range 2 {
				p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, dst)
				if e != nil {
					t.Fatal(e)
				}
				p.SetDeadline(time.Now().Add(3 * time.Second))
				for _, size := range []int{1, 31, 8192, 16000} {
					body := bytes.Repeat([]byte{byte(size)}, size)
					if _, e = p.WriteTo(body, netaddr.UDP(dst)); e != nil {
						t.Fatal(e)
					}
					b := make([]byte, 20000)
					count, _, e := p.ReadFrom(b)
					if e != nil || !bytes.Equal(b[:count], body) {
						t.Fatal("packet boundary/integrity", size, e)
					}
				}
				p.Close()
			}
		})
	}
	// A pending unauthenticated encryption handshake and an active connection are
	// both owned by runtime shutdown; no encrypted session may outlive it.
	pending, e := net.Dial("tcp", net.JoinHostPort(endpoint.Host, portString(endpoint.Port)))
	if e != nil {
		t.Fatal(e)
	}
	defer pending.Close()
	active, e := d.DialContext(ctx, netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr()))
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	if e = phaseExchange(active, []byte("active encrypted session")); e != nil {
		t.Fatal(e)
	}
	if e = h.Close(ctx); e != nil {
		t.Fatal(e)
	}
	for _, c := range []net.Conn{pending, active} {
		c.SetReadDeadline(time.Now().Add(time.Second))
		_, e = c.Read(make([]byte, 1))
		if e == nil {
			t.Fatal("shutdown left connection open")
		}
	}
	if h.Stats().Active != 0 {
		t.Fatal("orphan runtime session")
	}
}
