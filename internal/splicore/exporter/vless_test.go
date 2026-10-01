package exporter_test

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
	"strings"
	"testing"
	"time"
)

func vlessProfile(t *testing.T, host string) (clientprofile.Profile, string) {
	t.Helper()
	key, pub, err := v.GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	id := func() identity.ID {
		id, err := identity.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	stamp := identity.NewStamp(time.Now())
	inID, accountID, credentialID := id(), id(), id()
	settings, _ := json.Marshal(v.Settings{Security: v.Reality, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp", Reality: &v.RealitySettings{PublicKey: pub, ShortIDs: []v.ShortID{""}, ServerName: "target.test", Target: access.Endpoint{Host: "internal.test", Port: 443}}})
	i := access.Inbound{ID: inID, NodeID: id(), Name: "synthetic", Protocol: v.Key(v.Reality), Engine: "native", Enabled: true, Listeners: []access.Listener{{ID: id(), Transport: "tcp", Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 12345}}}, DisplayEndpoints: []access.DisplayEndpoint{{ID: id(), Endpoint: access.Endpoint{Host: host, Port: 443}}}, Tags: []string{}, Settings: access.Settings{Schema: 1, Data: settings}, Stamp: stamp}
	b := access.Binding{ID: id(), AccountID: accountID, InboundID: inID, CredentialID: credentialID, Enabled: true, Stamp: stamp}
	c := access.Credential{ID: credentialID, OwnerAccountID: &accountID, Kind: access.UUID, Schema: 1, State: "active", Payload: access.UUIDPayload{UUID: secret.New(string(id()))}, Stamp: stamp}
	p, err := (v.Module{Security: v.Reality}).BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: i, Binding: b, Credential: c})
	if err != nil {
		t.Fatal(err)
	}
	return p, key.Material.Reveal()
}
func TestVLESSExportSecretGateAndURI(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "2001:db8::1", "edge.test"} {
		p, private := vlessProfile(t, host)
		for _, target := range []ports.ExportTarget{{Format: ports.Mihomo, ClientVersion: "1.19.30"}, {Format: ports.SingBox, ClientVersion: "1.14.1"}, {Format: ports.URI}} {
			e := exporter.VLESS{Target: target.Format}
			b, err := e.Export(context.Background(), p, target)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), private) || strings.Contains(string(b), "private_key") || strings.Contains(string(b), "internal.test") || strings.Contains(string(b), "127.0.0.1:12345") {
				t.Fatal("BLOCKING SECURITY GATE")
			}
			if target.Format == ports.URI {
				uri, err := exporter.ParseVLESSURI(string(b))
				if err != nil || uri.Endpoint != p.Endpoint || uri.UUID.Reveal() != p.Credentials.(access.UUIDPayload).UUID.Reveal() || uri.Flow != v.NoFlow || uri.Security != v.Reality || uri.ShortID != "" || uri.ServerName != "target.test" {
					t.Fatal("URI roundtrip", err)
				}
				if strings.Contains(host, ":") && !strings.Contains(string(b), "[2001:db8::1]:443") {
					t.Fatal("IPv6 bracket encoding")
				}
				for _, bad := range []string{strings.Replace(string(b), "#", "&private_key=hidden#", 1), strings.Replace(string(b), "type=tcp", "type=ws", 1), strings.Replace(string(b), "security=reality", "security=tls", 1), strings.Replace(string(b), "sid=", "sid=a", 1), strings.Replace(string(b), "packetEncoding=xudp", "packetEncoding=packetaddr", 1)} {
					if _, err := exporter.ParseVLESSURI(bad); err == nil {
						t.Fatal("unsupported URI admitted")
					}
				}
			} else {
				var config map[string]any
				if json.Unmarshal(b, &config) != nil {
					t.Fatal("config parse")
				}
				if target.Format == ports.Mihomo {
					node := config["proxies"].([]any)[0].(map[string]any)
					if node["packet-encoding"] != "xudp" || node["flow"] != nil || node["servername"] != "target.test" {
						t.Fatal("Mihomo fields")
					}
				}
			}
		}
		for _, target := range []ports.ExportTarget{{Format: ports.Surge, ClientVersion: "6.7.0"}, {Format: ports.Mihomo, ClientVersion: "future"}, {Format: ports.SingBox, ClientVersion: "future"}} {
			if _, err := (exporter.VLESS{Target: target.Format}).Export(context.Background(), p, target); err == nil {
				t.Fatal("unqualified export admitted")
			}
		}
		p.Options.Data = []byte(`{"security":"reality","flow":"xtls-rprx-vision","packet_encoding":"xudp","private_key":"malicious"}`)
		if _, err := (exporter.VLESS{Target: ports.Mihomo}).Export(context.Background(), p, ports.ExportTarget{Format: ports.Mihomo, ClientVersion: "1.19.30"}); err == nil {
			t.Fatal("arbitrary secret options admitted")
		}
	}
}
func FuzzVLESSURI(f *testing.F) {
	uuid, err := identity.NewID()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("vless://" + string(uuid) + "@[2001:db8::1]:443?encryption=none&type=tcp&security=none&packetEncoding=xudp#synthetic")
	f.Fuzz(func(t *testing.T, s string) { _, _ = exporter.ParseVLESSURI(s) })
}
