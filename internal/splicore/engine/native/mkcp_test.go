package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	tm "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	vm "github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

// This fixture never borrows a port. The compiler receives a valid display
// intent; the test changes only the private handle's bind to UDP :0 before
// Start, then uses the actual owned listener address as the client endpoint.
func mkcpIntent(t *testing.T, protocol string, m cfg.MKCP, secure bool) (ports.RuntimeIntent, client.RemoteNode, access.Credential, tlsconfig.Settings) {
	t.Helper()
	id := func() identity.ID {
		v, e := identity.NewID()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	stamp := identity.NewStamp(time.Now())
	tr := cfg.Config{Kind: "mkcp", MKCP: &m}
	in := ports.RuntimeIntent{Inbound: access.Inbound{ID: id(), NodeID: id(), Name: "synthetic-mkcp", Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "udp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 1}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: "localhost", Port: 1}}}, Settings: access.Settings{Schema: 1}, Stamp: stamp}}
	account, cid := id(), id()
	key := access.UUIDPayload{UUID: secret.New("00000000-0000-1000-8000-000000000001")}
	credential := access.Credential{ID: cid, OwnerAccountID: &account, Kind: access.UUID, Schema: 1, State: "active", Payload: key, Stamp: stamp}
	var material tlsconfig.Settings
	security := "none"
	if secure || protocol == "trojan" {
		material = testkit.TLSForName(t, "mkcp.synthetic.test")
		security = "tls"
	}
	var options any
	switch protocol {
	case "vless":
		in.Inbound.Protocol = vl.Key(vl.Security(security))
		settings := vl.Settings{Security: vl.Security(security), Flow: vl.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Stream: &tr}
		if security == "tls" {
			settings.TLS = &material
		}
		in.Inbound.Settings.Data, _ = json.Marshal(settings)
		options = vl.ClientOptions{Security: vl.Security(security), Flow: vl.NoFlow, PacketEncoding: "xudp"}
	case "vmess":
		in.Inbound.Protocol = vm.Key()
		settings := vm.Settings{Transport: "tcp", Security: security, PayloadSecurity: "auto", Stream: &tr}
		if security == "tls" {
			settings.TLS = &material
		}
		in.Inbound.Settings.Data, _ = json.Marshal(settings)
		options = vm.ClientOptions{Security: "auto", UDP: true}
	case "trojan":
		in.Inbound.Protocol = tm.Key()
		in.Inbound.Settings.Data, _ = json.Marshal(tm.Settings{TLS: material, Stream: &tr})
		options = tm.ClientOptions{UDP: true}
		credential.Kind = access.Password
		credential.Payload = access.PasswordPayload{Password: secret.New("SyntheticMKCPPassword")}
	default:
		t.Fatal("unknown protocol")
	}
	in.Credentials = []access.Credential{credential}
	in.Bindings = []access.Binding{{ID: id(), AccountID: account, InboundID: in.Inbound.ID, CredentialID: cid, Enabled: true, Stamp: stamp}}
	nid, nodeCID := id(), id()
	node := client.RemoteNode{ID: nid, Name: "synthetic-mkcp-node", Protocol: in.Inbound.Protocol, Endpoint: in.Inbound.Listeners[0].Endpoint, CredentialID: nodeCID, Transport: tr, Security: client.Security{Kind: security}, Options: client.Options{Schema: 1}}
	node.Options.Data, _ = json.Marshal(options)
	if security == "tls" {
		node.Security.TLS = access.ClientTLS{Enabled: true, ServerName: material.ServerName, Trust: "explicit_ca", CACertificate: material.CACertificate}
	}
	credential.ID = nodeCID
	credential.OwnerAccountID = nil
	credential.OwnerNodeID = &nid
	return in, node, credential, material
}
func startMKCP(t *testing.T, ctx context.Context, protocol string, in ports.RuntimeIntent, host string) (ports.RuntimeHandle, access.Endpoint) {
	t.Helper()
	handle := sharedPrepare(t, ctx, protocol, in)
	switch h := handle.(type) {
	case *vlessHandle:
		h.endpoint = access.Endpoint{Host: host}
	case *vmessHandle:
		h.endpoint = access.Endpoint{Host: host}
	case *trojanHandle:
		h.endpoint = access.Endpoint{Host: host}
	}
	if e := handle.Start(ctx); e != nil {
		t.Fatal(e)
	}
	handle.Activate()
	t.Cleanup(func() { handle.Close(context.Background()) })
	var addr net.Addr
	switch h := handle.(type) {
	case *vlessHandle:
		addr = h.listener.Addr()
	case *vmessHandle:
		addr = h.listener.Addr()
	case *trojanHandle:
		addr = h.listener.Addr()
	}
	return handle, netaddrEndpoint(addr)
}
func TestMKCPNativeProtocolComposition(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	udp := trojanUDP(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			m := cfg.DefaultMKCP()
			m.TTI = 10
			in, node, key, _ := mkcpIntent(t, protocol, m, protocol == "trojan")
			handle, endpoint := startMKCP(t, ctx, protocol, in, "127.0.0.1")
			node.Endpoint = endpoint
			dialer := sharedBuild(t, ctx, node, key)
			t.Cleanup(func() { dialer.Close() })
			sharedPayload(t, dialer, target, udp)
			handle.Close(ctx)
		})
	}
}
func TestMKCPNativeTLSCompositions(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	target := netaddrEndpoint(vmessTCP(t, "127.0.0.1:0").Addr())
	for _, protocol := range []string{"vless", "vmess"} {
		t.Run(protocol, func(t *testing.T) {
			m := cfg.DefaultMKCP()
			m.TTI = 10
			in, node, key, _ := mkcpIntent(t, protocol, m, true)
			_, node.Endpoint = startMKCP(t, ctx, protocol, in, "127.0.0.1")
			dialer := sharedBuild(t, ctx, node, key)
			defer dialer.Close()
			c, e := dialer.DialContext(ctx, target)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Write([]byte("TLS over reliable UDP"))
			b := make([]byte, 21)
			_, e = io.ReadFull(c, b)
			if e != nil || !bytes.Equal(b, []byte("TLS over reliable UDP")) {
				t.Fatal(e, string(b))
			}
		})
	}
}

func TestMKCPManagedCarrierCapabilitiesAndLegacyError(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			in, _, _, _ := mkcpIntent(t, protocol, cfg.DefaultMKCP(), protocol == "trojan")
			var decode func(json.RawMessage) (ports.CreationDraft, error)
			var validate func(access.Inbound) error
			var kinds []string
			switch protocol {
			case "vless":
				m := vl.Module{Security: vl.Plain}
				decode = m.DecodeCreation
				validate = m.ValidateInbound
				kinds = m.Capabilities(ports.CapabilityContext{}).Transport.Kinds
			case "vmess":
				m := vm.Module{}
				decode = m.DecodeCreation
				validate = m.ValidateInbound
				kinds = m.Capabilities(ports.CapabilityContext{}).Transport.Kinds
			case "trojan":
				m := tm.Module{}
				decode = m.DecodeCreation
				validate = m.ValidateInbound
				kinds = m.Capabilities(ports.CapabilityContext{}).Transport.Kinds
			}
			found := false
			for _, kind := range kinds {
				if kind == "mkcp" {
					found = true
				}
			}
			if !found {
				t.Fatal("capability missing")
			}
			if e := validate(in.Inbound); e != nil {
				t.Fatal(e)
			}
			wrong := in.Inbound
			wrong.Listeners = append([]access.Listener(nil), wrong.Listeners...)
			wrong.Listeners[0].Transport = "tcp"
			if validate(wrong) == nil {
				t.Fatal("wrong carrier accepted")
			}
			user := map[string]any{"account_name": "synthetic"}
			if protocol == "trojan" {
				user["password"] = "SyntheticMKCPPassword"
			} else {
				user["uuid"] = "00000000-0000-1000-8000-000000000001"
			}
			doc := map[string]any{"schema": 1, "name": "mkcp-owned", "listener": in.Inbound.Listeners[0].Endpoint, "display_endpoint": in.Inbound.DisplayEndpoints[0].Endpoint, "settings": in.Inbound.Settings.Data, "users": []any{user}}
			b, _ := json.Marshal(doc)
			draft, e := decode(b)
			if e != nil || draft.Transport != "udp" {
				t.Fatal("creation carrier", draft.Transport, e)
			}
			var settings map[string]any
			_ = json.Unmarshal(in.Inbound.Settings.Data, &settings)
			settings["stream_transport"] = map[string]any{"kind": "mkcp", "mkcp": map[string]any{"seed": "old"}}
			doc["settings"] = settings
			b, _ = json.Marshal(doc)
			if _, e = decode(b); !errors.Is(e, cfg.ErrLegacyMKCP) {
				t.Fatal("lost legacy migration error", e)
			}
		})
	}
}
