package access_test

import (
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

func TestClientTLSJLSIsExplicitAndExclusive(t *testing.T) {
	good := access.ClientTLS{Enabled: true, ServerName: "cover.test", ALPN: []string{"h3"}, Trust: "jls"}
	if e := good.Validate("jls"); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*access.ClientTLS){func(c *access.ClientTLS) { c.Trust = "system" }, func(c *access.ClientTLS) { c.Enabled = false }, func(c *access.ClientTLS) { c.ServerName = "" }, func(c *access.ClientTLS) { c.ALPN = []string{"h2"} }, func(c *access.ClientTLS) { c.CACertificate = "unexpected" }, func(c *access.ClientTLS) { c.RealityPublicKey = "unexpected" }} {
		bad := good
		change(&bad)
		if bad.Validate("jls") == nil {
			t.Fatal("invalid JLS trust combination")
		}
	}
	if good.Validate("tls") == nil || good.Validate("none") == nil || good.Validate("reality") == nil {
		t.Fatal("JLS trust escaped security kind")
	}
}
