package native

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"testing"
	"time"
)

func FuzzSnellOutboundOptions(f *testing.F) {
	f.Add(`{"version":5}`)
	f.Add(`{"version":6}`)
	f.Add(`{"version":7}`)
	f.Add(`{"version":5,"psk":"forbidden"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 16385 {
			return
		}
		id := identity.ID("00000000-0000-4000-8000-000000000001")
		cid := identity.ID("00000000-0000-4000-8000-000000000002")
		n := client.RemoteNode{ID: id, Name: "synthetic", Protocol: module.Key(5), Endpoint: access.Endpoint{Host: "localhost", Port: 12345}, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(raw)}}
		c := access.Credential{ID: cid, OwnerNodeID: &id, Kind: access.PSK, Schema: 1, State: "active", Payload: access.PSKPayload{Key: secret.New("SyntheticFuzzPSK12345")}, Stamp: identity.NewStamp(time.Now())}
		_ = (SnellOutboundFactory{}).Validate(n, c)
	})
}
