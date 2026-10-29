package networkruntime

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
)

func TestWireGuardCredentialAndServerRouting(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	m, err := Compile(P.Config{Route: P.RouteProfile{Rules: []P.RouteRule{{ID: testID(1), Match: P.RuleMatch{EndpointTags: []string{"core-wg"}, PeerPublicKeys: []string{key}}, Action: P.Action{Kind: P.Reject}}, {ID: testID(2), Match: P.RuleMatch{ServerInbounds: []identity.ID{testID(5)}}, Action: P.Action{Kind: P.Reject}}, {ID: testID(3), Action: P.Action{Kind: P.Outbound, ID: testID(7)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	query := Query{IP: netip.MustParseAddr("192.0.2.1"), Network: "tcp", Port: 443, EndpointTag: "core-wg", PeerPublicKey: key}
	if query.Validate() != nil || m.Match(query, P.Action{Kind: P.Direct}, false).Rule != testID(1) {
		t.Fatal("credential rule did not match")
	}
	query.EndpointTag = "other"
	if m.Match(query, P.Action{Kind: P.Direct}, false).Rule != testID(3) {
		t.Fatal("unrelated endpoint matched credential")
	}
	query.EndpointTag = ""
	query.PeerPublicKey = ""
	query.ServerInbound = testID(5)
	if m.Match(query, P.Action{Kind: P.Direct}, false).Rule != testID(2) {
		t.Fatal("explicit server scope did not match")
	}
	query.ServerInbound = testID(6)
	if got := m.Match(query, P.Action{Kind: P.Direct}, false); got.Action.Kind != P.Direct {
		t.Fatal("client rule escaped into server flow")
	}
	query.ServerInbound = ""
	query.EndpointTag = "core-wg"
	if query.Validate() == nil {
		t.Fatal("incomplete credential accepted")
	}
	query.PeerPublicKey = "invalid"
	if query.Validate() == nil {
		t.Fatal("invalid credential accepted")
	}
}
