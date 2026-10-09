package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/engine/netaddr"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func sharedIntent(t *testing.T, protocol, kind string, secure bool) (ports.RuntimeIntent, client.RemoteNode, access.Credential) {
	t.Helper()
	c := cfg.Config{Kind: kind, Path: "/shared-core", Host: "core.synthetic.test"}
	if kind == "grpc" {
		c.Path = ""
		c.Host = ""
		c.ServiceName = "SharedCore"
	}
	var in ports.RuntimeIntent
	var n client.RemoteNode
	var credential access.Credential
	switch protocol {
	case "vmess":
		in = vmessIntent(t, secure)
		s, e := vm.Decode(in.Inbound.Settings.Data)
		if e != nil {
			t.Fatal(e)
		}
		s.Stream = &c
		in.Inbound.Settings.Data, _ = json.Marshal(s)
		n, credential = vmessNode(t, in, 0, "auto")
	case "trojan":
		intent, m := trojanIntent(t)
		in = intent
		s, e := tm.Decode(in.Inbound.Settings.Data)
		if e != nil {
			t.Fatal(e)
		}
		s.Stream = &c
		in.Inbound.Settings.Data, _ = json.Marshal(s)
		n, credential = trojanNode(t, in, m, 0)
	case "vless":
		in = vmessIntent(t, secure)
		s, e := vm.Decode(in.Inbound.Settings.Data)
		if e != nil {
			t.Fatal(e)
		}
		security := vl.Plain
		if secure {
			security = vl.TLS
		}
		in.Inbound.Protocol = vl.Key(security)
		in.Inbound.Settings.Data, _ = json.Marshal(vl.Settings{Security: security, Flow: vl.NoFlow, Transport: "tcp", PacketEncoding: "xudp", TLS: s.TLS, Stream: &c})
		for i := range in.Credentials {
			id, _ := identity.NewID()
			in.Credentials[i].Payload = access.UUIDPayload{UUID: secret.New(string(id))}
		}
		id, _ := identity.NewID()
		cid, _ := identity.NewID()
		n = client.RemoteNode{ID: id, Name: "synthetic-VLESS-shared", Protocol: in.Inbound.Protocol, Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: cid, Transport: c, Security: client.Security{Kind: string(security)}, Options: client.Options{Schema: 1}}
		n.Options.Data, _ = json.Marshal(vl.ClientOptions{Security: security, Flow: vl.NoFlow, PacketEncoding: "xudp"})
		if secure {
			n.Security.TLS = access.ClientTLS{Enabled: true, ServerName: s.TLS.ServerName, Trust: "explicit_ca", CACertificate: s.TLS.CACertificate}
		}
		credential = in.Credentials[0]
		credential.ID = cid
		credential.OwnerAccountID = nil
		credential.OwnerNodeID = &id
	default:
		t.Fatal("unknown test protocol")
	}
	n.Transport = c
	return in, n, credential
}
func sharedPrepare(t *testing.T, ctx context.Context, protocol string, in ports.RuntimeIntent) ports.RuntimeHandle {
	t.Helper()
	var p ports.PreparedRuntime
	var e error
	switch protocol {
	case "vmess":
		p, e = NewVMessCompiler().Compile(ctx, in)
	case "vless":
		p, e = (VLESSCompiler{}).Compile(ctx, in)
	case "trojan":
		p, e = (TrojanCompiler{}).Compile(ctx, in)
	}
	if e != nil {
		t.Fatal(e)
	}
	return p.(ports.RuntimeHandle)
}
func sharedBuild(t *testing.T, ctx context.Context, n client.RemoteNode, c access.Credential) ports.ClientDialer {
	t.Helper()
	var d ports.ClientDialer
	var e error
	switch n.Protocol.Protocol {
	case "vmess":
		d, e = (VMessOutboundFactory{}).Build(ctx, n, c)
	case "vless":
		d, e = (VLESSOutboundFactory{}).Build(ctx, n, c)
	case "trojan":
		d, e = (TrojanOutboundFactory{}).Build(ctx, n, c)
	}
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func sharedPayload(t *testing.T, d ports.ClientDialer, tcp, udp access.Endpoint) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, e := d.DialContext(ctx, tcp)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := bytes.Repeat([]byte("shared-transport-payload"), 7000)
	done := make(chan error, 1)
	go func() { _, e := c.Write(payload); done <- e }()
	got := make([]byte, len(payload))
	if _, e = io.ReadFull(c, got); e != nil {
		t.Fatal("TCP reply", e)
	}
	if e = <-done; e != nil || !bytes.Equal(got, payload) {
		t.Fatal("TCP mismatch", e)
	}
	c.Close()
	p, e := d.(ports.ClientPacketDialer).ListenPacket(ctx, udp)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	p.SetDeadline(time.Now().Add(5 * time.Second))
	body := bytes.Repeat([]byte("udp"), 300)
	if _, e = p.WriteTo(body, netaddr.UDP(udp)); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 2000)
	n, _, e := p.ReadFrom(b)
	if e != nil || !bytes.Equal(body, b[:n]) {
		t.Fatal("UDP mismatch", e)
	}
}
func TestNativeSharedTransportMatrix(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
			for _, secure := range []bool{false, true} {
				if protocol == "trojan" && !secure {
					continue
				}
				t.Run(protocol+"-"+kind+map[bool]string{false: "-plain", true: "-tls"}[secure], func(t *testing.T) {
					in, n, c := sharedIntent(t, protocol, kind, secure)
					h := sharedPrepare(t, ctx, protocol, in)
					if e := h.Start(ctx); e != nil {
						t.Fatal(e)
					}
					h.Activate()
					d := sharedBuild(t, ctx, n, c)
					sharedPayload(t, d, tcp, udp)
					d.Close()
					if e := h.Close(ctx); e != nil {
						t.Fatal(e)
					}
					if h.Stats().Active != 0 {
						t.Fatal("active sessions after close")
					}
				})
			}
		}
	}
}

func TestNativeGRPCSeparatedIdentity(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	tcp := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vmess", "vless", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			in, n, c := sharedIntent(t, protocol, "grpc", true)
			n.Transport.Host = "authority.synthetic.test"
			if n.Security.TLS.ServerName == n.Transport.Host || n.Security.TLS.Trust != "explicit_ca" {
				t.Fatal("invalid separation fixture")
			}
			h := sharedPrepare(t, ctx, protocol, in)
			if err := h.Start(ctx); err != nil {
				t.Fatal(err)
			}
			h.Activate()
			defer h.Close(ctx)
			d := sharedBuild(t, ctx, n, c)
			defer d.Close()
			sharedPayload(t, d, tcp, udp)
			t.Logf("endpoint=%s SNI=%s authority=%s verified TLS TCP168000/UDP900 reply PASS", netaddr.TCP(n.Endpoint), n.Security.TLS.ServerName, n.Transport.Host)
		})
	}
}
