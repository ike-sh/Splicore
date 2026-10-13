package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestNativeXHTTPSharedProtocols(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				in, n, c := sharedIntent(t, protocol, "xhttp", true)
				n.Transport.XHTTP = &cfg.XHTTP{Mode: mode}
				var settings map[string]json.RawMessage
				_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
				settings["stream_transport"], _ = json.Marshal(n.Transport)
				in.Inbound.Settings.Data, _ = json.Marshal(settings)
				h := sharedPrepare(t, ctx, protocol, in)
				if e := h.Start(ctx); e != nil {
					t.Fatal(e)
				}
				h.Activate()
				defer h.Close(ctx)
				d := sharedBuild(t, ctx, n, c)
				defer d.Close()
				sharedPayload(t, d, tcp, udp)
			})
		}
	}
}

func TestNativeXHTTPDelayedFirstPacket(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			in, n, credential := sharedIntent(t, protocol, "xhttp", true)
			n.Transport.XHTTP = &cfg.XHTTP{Mode: "packet-up", Interval: cfg.Range{Min: 6000, Max: 6000}}
			var settings map[string]json.RawMessage
			_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
			serverTransport := n.Transport.Clone()
			serverTransport.XHTTP.Interval = cfg.Range{}
			settings["stream_transport"], _ = json.Marshal(serverTransport)
			in.Inbound.Settings.Data, _ = json.Marshal(settings)
			h := sharedPrepare(t, ctx, protocol, in)
			if err := h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			defer h.Close(ctx)
			d := sharedBuild(t, ctx, n, credential)
			defer d.Close()
			c, err := d.DialContext(ctx, tcp)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(15 * time.Second))
			if _, err = c.Write([]byte("A")); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 1)
			if _, err = io.ReadFull(c, b); err != nil || string(b) != "A" {
				t.Fatal("delayed native admission", string(b), err)
			}
		})
	}
}

func TestNativeXHTTPFragmentedAdmission(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(underlay.WithFactory(context.Background(), underlay.New()), 90*time.Second)
			defer cancel()
			tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
			in, n, credential := sharedIntent(t, protocol, "xhttp", true)
			n.Transport.XHTTP = &cfg.XHTTP{Mode: "packet-up", PacketBytes: cfg.Range{16, 16}, Interval: cfg.Range{6000, 6000}}
			serverTransport := n.Transport.Clone()
			serverTransport.XHTTP.Interval = cfg.Range{}
			var settings map[string]json.RawMessage
			_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
			settings["stream_transport"], _ = json.Marshal(serverTransport)
			in.Inbound.Settings.Data, _ = json.Marshal(settings)
			h := sharedPrepare(t, ctx, protocol, in)
			if err := h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			defer h.Close(ctx)
			d := sharedBuild(t, ctx, n, credential)
			defer d.Close()
			c, err := d.DialContext(ctx, tcp)
			if err != nil {
				t.Fatal("fragmented admission write", err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(60 * time.Second))
			want := []byte("A")
			if _, err = c.Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 1)
			if _, err = io.ReadFull(c, got); err != nil || string(got) != "A" {
				t.Fatal("fragmented native authentication", got, err)
			}
		})
	}
}

func TestNativeXHTTPRealityModes(t *testing.T) {
	if !vl.RealityCompiled {
		t.Skip("REALITY requires with_utls")
	}
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	m := testkit.TLSForName(t, "target.synthetic.test")
	cert, _ := os.ReadFile(m.CertificateFile)
	key, _ := os.ReadFile(m.PrivateKeyFile)
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	target := vlessEcho(t, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		t.Run(mode, func(t *testing.T) {
			in, n, c := sharedIntent(t, "vless", "xhttp", true)
			private, public, e := vl.GenerateServerKey()
			if e != nil {
				t.Fatal(e)
			}
			n.Transport.XHTTP = &cfg.XHTTP{Mode: mode}
			n.Protocol = vl.Key(vl.Reality)
			n.Security.Kind = "reality"
			n.Security.TLS = access.ClientTLS{Enabled: true, ServerName: m.ServerName, Trust: "reality", RealityPublicKey: string(public), RealityShortID: "abcd", ALPN: []string{"h2"}}
			n.Options.Data, _ = json.Marshal(vl.ClientOptions{Security: vl.Reality, Flow: vl.NoFlow, PacketEncoding: "xudp"})
			in.Inbound.Protocol = n.Protocol
			in.Inbound.Settings.Data, _ = json.Marshal(vl.Settings{Security: vl.Reality, Flow: vl.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Stream: &n.Transport, Reality: &vl.RealitySettings{PublicKey: public, ServerName: m.ServerName, ShortIDs: []vl.ShortID{"abcd"}, Target: access.Endpoint{Host: "127.0.0.1", Port: uint16(target.Addr().(*net.TCPAddr).Port)}}})
			id, _ := identity.NewID()
			in.ServerCredentials = []access.Credential{{ID: id, OwnerInboundID: &in.Inbound.ID, Kind: access.PrivateKey, Schema: 1, State: "active", Payload: private, Stamp: identity.NewStamp(time.Now())}}
			h := sharedPrepare(t, ctx, "vless", in)
			if e := h.Start(ctx); e != nil {
				t.Fatal(e)
			}
			h.Activate()
			defer h.Close(ctx)
			d := sharedBuild(t, ctx, n, c)
			defer d.Close()
			sharedPayload(t, d, tcp, udp)
		})
	}
}
