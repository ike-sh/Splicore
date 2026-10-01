package exporter

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"strings"
	"testing"
)

func profile(v int, host string) clientprofile.Profile {
	id, _ := identity.NewID()
	return clientprofile.Profile{ID: id, Schema: 1, Protocol: snell.Key(v), Endpoint: access.Endpoint{Host: host, Port: 24443}, Credentials: access.PSKPayload{Key: secret.New("SyntheticPhase2TestKey0001")}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: json.RawMessage(fmt.Sprintf(`{"version":%d}`, v))}, Metadata: identity.Metadata{}}
}
func TestExportContracts(t *testing.T) {
	for _, host := range []string{"192.0.2.7", "2001:db8::7", "node.example.invalid"} {
		for _, v := range []int{5, 6} {
			p := profile(v, host)
			wire := v
			if wire == 5 {
				wire = 4
			}
			for _, target := range []ports.ExportTarget{{Format: ports.Mihomo, ClientVersion: "1.19.30"}, {Format: ports.SingBox, ClientVersion: "1.14.1"}, {Format: ports.Surge, ClientVersion: "mac-6.7.0"}} {
				b, e := (Snell{target.Format}).Export(context.Background(), p, target)
				if target.Format == ports.Mihomo && v == 6 {
					if e == nil {
						t.Fatal("Mihomo v6 accepted")
					}
					continue
				}
				if e != nil {
					t.Fatal(e)
				}
				if target.Format == ports.Surge {
					if !strings.Contains(string(b), host) || !strings.HasSuffix(string(b), fmt.Sprintf("version=%d", wire)) || strings.Contains(string(b), "udp-relay") {
						t.Fatal("Surge contract")
					}
				} else {
					var m map[string]any
					if json.Unmarshal(b, &m) != nil || m["server"] != host || m["version"] != float64(wire) {
						t.Fatal("JSON contract")
					}
				}
			}
		}
	}
	p := profile(5, "192.0.2.7")
	for _, target := range []ports.ExportTarget{{Format: ports.URI}, {Format: ports.SingBox, ClientVersion: "latest"}, {Format: ports.Surge, ClientVersion: "old"}} {
		if _, e := (Snell{target.Format}).Export(context.Background(), p, target); e == nil {
			t.Fatal("unsupported export accepted")
		}
	}
	b, _ := json.Marshal(p)
	if strings.Contains(string(b), "SyntheticPhase2TestKey0001") || strings.Contains(fmt.Sprintf("%+v", p), "SyntheticPhase2TestKey0001") {
		t.Fatal("profile leak")
	}
}
func FuzzExport(f *testing.F) {
	f.Add("2001:db8::7", "SyntheticPhase2TestKey0001")
	f.Add("host, injection", "key\nsecret")
	f.Fuzz(func(t *testing.T, host, key string) {
		p := profile(5, host)
		p.Credentials = access.PSKPayload{Key: secret.New(key)}
		for _, target := range []ports.ExportTarget{{Format: ports.Mihomo, ClientVersion: "1.19.30"}, {Format: ports.SingBox, ClientVersion: "1.14.1"}, {Format: ports.Surge, ClientVersion: "mac-6.7.0"}} {
			b, e := (Snell{target.Format}).Export(context.Background(), p, target)
			if e == nil {
				if target.Format != ports.Surge && !json.Valid(b) {
					t.Fatal("invalid JSON")
				}
				if strings.ContainsAny(string(b), "\r\n") {
					t.Fatal("unescaped line injection")
				}
			}
		}
	})
}
