//go:build with_quic

package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func phase31Intent(t *testing.T, protocol, kind string) ports.RuntimeIntent {
	t.Helper()
	in, n, _ := sharedIntent(t, protocol, "h2", true)
	n.Transport.Kind = kind
	if kind == "quic-stream" {
		n.Transport.Path = ""
		n.Transport.Host = ""
	}
	var settings map[string]json.RawMessage
	if e := json.Unmarshal(in.Inbound.Settings.Data, &settings); e != nil {
		t.Fatal(e)
	}
	settings["stream_transport"], _ = json.Marshal(n.Transport)
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	for i := range in.Inbound.Listeners {
		in.Inbound.Listeners[i].Transport = n.Transport.Carrier()
	}
	return in
}

func TestPhase31ProtocolComposition(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, kind := range []string{"http", "h2", "quic-stream"} {
			t.Run(protocol+"/"+kind, func(t *testing.T) {
				in, n, c := sharedIntent(t, protocol, "h2", true)
				n.Transport.Kind = kind
				if kind == "quic-stream" {
					n.Transport.Path = ""
					n.Transport.Host = ""
				}
				var settings map[string]json.RawMessage
				_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
				settings["stream_transport"], _ = json.Marshal(n.Transport)
				in.Inbound.Settings.Data, _ = json.Marshal(settings)
				for i := range in.Inbound.Listeners {
					in.Inbound.Listeners[i].Transport = n.Transport.Carrier()
				}
				h, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
				n.Endpoint = endpoint
				d := sharedBuild(t, ctx, n, c)
				sharedPayload(t, d, tcp, udp)
				d.Close()
				if e := h.Close(ctx); e != nil {
					t.Fatal(e)
				}
				if h.Stats().Active != 0 {
					t.Fatal("orphan sessions")
				}
				// Real runtime restart uses a fresh compiled generation and same committed intent.
				h2, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
				n.Endpoint = endpoint
				d2 := sharedBuild(t, ctx, n, c)
				sharedPayload(t, d2, tcp, udp)
				d2.Close()
				h2.Close(ctx)
			})
		}
	}
}

func TestPhase31FailedBind(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	for _, kind := range []string{"http", "h2", "quic-stream"} {
		t.Run(kind, func(t *testing.T) {
			in := phase31Intent(t, "vless", kind)
			h, ep := startMKCP(t, ctx, "vless", in, "127.0.0.1")
			defer h.Close(ctx)
			other := sharedPrepare(t, ctx, "vless", in)
			other.(*vlessHandle).endpoint = access.Endpoint{Host: ep.Host, Port: ep.Port}
			if e := other.Start(ctx); e == nil {
				other.Close(ctx)
				t.Fatal("bind conflict accepted")
			}
			other.Close(ctx)
		})
	}
}

func TestPhase31ManagedDNS(t *testing.T) {
	for _, kind := range []string{"http", "h2", "quic-stream"} {
		for _, host := range []string{"transport.synthetic.invalid", "nxdomain.synthetic.invalid", "127.0.0.1", "::1"} {
			t.Run(kind+"/"+host, func(t *testing.T) {
				calls := &atomic.Int32{}
				lookup := func(_ context.Context, h string) ([]netip.Addr, error) {
					calls.Add(1)
					if h == "transport.synthetic.invalid" {
						return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
					}
					return nil, &net.DNSError{Name: h, Err: "no such host", IsNotFound: true}
				}
				ctx := underlay.WithBootstrap(underlay.WithFactory(context.Background(), underlay.New()), lookup)
				in, n, c := sharedIntent(t, "vless", "h2", true)
				n.Transport.Kind = kind
				if kind == "quic-stream" {
					n.Transport.Path = ""
					n.Transport.Host = ""
				}
				var settings map[string]json.RawMessage
				_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
				settings["stream_transport"], _ = json.Marshal(n.Transport)
				in.Inbound.Settings.Data, _ = json.Marshal(settings)
				in.Inbound.Listeners[0].Transport = n.Transport.Carrier()
				bind := "127.0.0.1"
				if host == "::1" {
					bind = "::1"
				}
				h, ep := startMKCP(t, ctx, "vless", in, bind)
				defer h.Close(ctx)
				n.Endpoint = ep
				n.Endpoint.Host = host
				d := sharedBuild(t, ctx, n, c)
				defer d.Close()
				target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
				admission, cancel := context.WithTimeout(ctx, 3*time.Second)
				defer cancel()
				stream, e := d.DialContext(admission, target)
				if host == "nxdomain.synthetic.invalid" {
					if e == nil {
						stream.Close()
						t.Fatal("NXDOMAIN bypassed")
					}
					if calls.Load() != 1 {
						t.Fatal("managed lookup not used", calls.Load())
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = stream.Write([]byte("dns")); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 3)
				if _, e = io.ReadFull(stream, b); e != nil || string(b) != "dns" {
					t.Fatal(string(b), e)
				}
				want := int32(0)
				if host == "transport.synthetic.invalid" {
					want = 1
				}
				if calls.Load() != want {
					t.Fatal("literal resolution or managed lookup mismatch", calls.Load(), want)
				}
			})
		}
	}
}

func TestPhase31ProtocolAuthentication(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, kind := range []string{"http", "h2", "quic-stream"} {
			t.Run(protocol+"/"+kind, func(t *testing.T) {
				in, n, c := sharedIntent(t, protocol, "h2", true)
				n.Transport.Kind = kind
				if kind == "quic-stream" {
					n.Transport.Path = ""
					n.Transport.Host = ""
				}
				var settings map[string]json.RawMessage
				_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
				settings["stream_transport"], _ = json.Marshal(n.Transport)
				in.Inbound.Settings.Data, _ = json.Marshal(settings)
				in.Inbound.Listeners[0].Transport = n.Transport.Carrier()
				h, ep := startMKCP(t, ctx, protocol, in, "127.0.0.1")
				defer h.Close(ctx)
				n.Endpoint = ep
				if protocol == "trojan" {
					c.Payload = access.PasswordPayload{Password: secret.New("not-the-protocol-password")}
				} else {
					c.Payload = access.UUIDPayload{UUID: secret.New("00000000-0000-4000-8000-000000000099")}
				}
				d := sharedBuild(t, ctx, n, c)
				defer d.Close()
				stream, e := d.DialContext(ctx, target)
				if e != nil {
					return
				}
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(time.Second))
				stream.Write([]byte("must not authenticate through TLS/HTTP headers"))
				if _, e = stream.Read(make([]byte, 1)); e == nil {
					t.Fatal("transport identity bypassed protocol credentials")
				}
			})
		}
	}
}
