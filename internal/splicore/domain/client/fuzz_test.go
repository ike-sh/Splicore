package client_test

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"testing"
)

func FuzzCanonicalNodeOptions(f *testing.F) {
	f.Add([]byte(`{"version":6}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"engine_options":{"finalmask":{}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		n := client.RemoteNode{ID: "68f4f564-142b-46b3-8c89-322a37ef1b30", Name: "synthetic", Protocol: access.ProtocolKey{Protocol: "snell", WireVersion: "6", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "localhost", Port: 443}, CredentialID: "a6f4f564-142b-46b3-8c89-322a37ef1b30", Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: b}, Metadata: identity.Metadata{}}
		_ = n.Validate()
		var decoded client.RemoteNode
		_ = jsonstrict.Decode(b, &decoded)
		_ = decoded.Validate()
	})
}
