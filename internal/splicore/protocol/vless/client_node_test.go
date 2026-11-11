package vless

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"testing"
)

func FuzzREALITYClientPublicOptions(f *testing.F) {
	f.Add("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "abcd", "synthetic.test", []byte(`{"security":"reality","flow":"none","packet_encoding":"xudp"}`))
	f.Fuzz(func(t *testing.T, key, id, name string, options []byte) {
		owner := client.RemoteNode{ID: "68f4f564-142b-46b3-8c89-322a37ef1b30", Name: "synthetic", Protocol: Key(Reality), Endpoint: access.Endpoint{Host: "localhost", Port: 443}, CredentialID: "a6f4f564-142b-46b3-8c89-322a37ef1b30", Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "reality", TLS: access.ClientTLS{Enabled: true, ServerName: name, RealityPublicKey: key, RealityShortID: id}}, Options: client.Options{Schema: 1, Data: options}}
		c := access.Credential{ID: owner.CredentialID, OwnerNodeID: &owner.ID, Kind: access.UUID, State: "active", Payload: access.UUIDPayload{UUID: secret.New("78f4f564-142b-46b3-8c89-322a37ef1b30")}}
		_ = ValidateClientNode(owner, c)
		var settings access.ClientTLS
		_ = json.Unmarshal(options, &settings)
	})
}
