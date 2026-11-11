package nodeimport

import (
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"strings"
	"testing"
)

func TestSnellV4ExternalRoundTripAndLimits(t *testing.T) {
	p := snellProfile(4, "2001:db8::1")
	p.Options.Data = json.RawMessage(`{"version":4,"reuse":true,"obfs_mode":"http","obfs_host":"cover.example"}`)
	for _, target := range []ports.ExportTarget{{Format: ports.SingBox, ClientVersion: "1.14.3"}, {Format: ports.Mihomo, ClientVersion: "1.19.32"}} {
		b, e := (exporter.Snell{Target: target.Format}).Export(context.Background(), p, target)
		if e != nil {
			t.Fatal(e)
		}
		format := "sing-box"
		if target.Format == ports.Mihomo {
			format = "mihomo"
			b = append(append([]byte(`{"proxies":[`), b...), []byte(`]}`)...)
		}
		parsed, e := Parse(format, b)
		if e != nil || len(parsed.Candidates) != 1 || len(parsed.Issues) != 0 {
			t.Fatal(format, e, parsed.Issues)
		}
		n := parsed.Candidates[0].Node
		o, e := sm.DecodeClient(n.Options.Data)
		if e != nil || n.Protocol != sm.Key(4) || n.Endpoint != p.Endpoint || !o.Reuse || o.ObfsMode != "http" || o.ObfsHost != "cover.example" {
			t.Fatal(format, o, e)
		}
		p.Options.Data = json.RawMessage(`{"version":4,"obfs_mode":"http","obfs_uri":"/custom"}`)
		if _, e := (exporter.Snell{Target: target.Format}).Export(context.Background(), p, target); e == nil {
			t.Fatal("custom URI lost")
		}
		p.Options.Data = json.RawMessage(`{"version":4,"udp_port":24444}`)
		if _, e := (exporter.Snell{Target: target.Format}).Export(context.Background(), p, target); e == nil {
			t.Fatal("UDP endpoint lost")
		}
		p.Options.Data = json.RawMessage(`{"version":4,"reuse":true,"obfs_mode":"http","obfs_host":"cover.example"}`)
	}
	d, e := (exporter.Snell{Target: ports.SingBox}).Describe(snellProfile(5, "localhost"))
	if e != nil || d.ClientWireVersion != 4 || !strings.Contains(d.Compatibility, "v5 server") {
		t.Fatal(d, e)
	}
}

func snellProfile(v int, host string) clientprofile.Profile {
	id, _ := identity.NewID()
	raw, _ := json.Marshal(map[string]int{"version": v})
	return clientprofile.Profile{ID: id, Schema: 1, Protocol: sm.Key(v), Endpoint: access.Endpoint{Host: host, Port: 24443}, Credentials: access.PSKPayload{Key: secret.New("SyntheticRoundtripPSK1234")}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: raw}, Metadata: identity.Metadata{}}
}
