// Package proxy validates generic upstream proxy node intent. It is not a
// managed encrypted server protocol and has no routing or persistence.
package proxy

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/engine/clientconfig"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/socks5"
	"strings"
)

const NoAuth = "no_authentication"

type Options struct {
	Auth bool `json:"auth"`
	UDP  bool `json:"udp"`
}

func Key(protocol string) access.ProtocolKey {
	version := "5"
	if protocol == "http" {
		version = "1.1"
	}
	return access.ProtocolKey{Protocol: protocol, WireVersion: version, FeatureProfile: "base"}
}
func Invalid() error {
	return identity.Err(identity.Invalid, "invalid upstream proxy settings or credential")
}
func Decode(b []byte) (Options, error) {
	var o Options
	if len(b) > 1024 || jsonstrict.Decode(b, &o) != nil {
		return o, Invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil || fields == nil {
		return o, Invalid()
	}
	for _, v := range fields {
		if strings.TrimSpace(string(v)) == "null" {
			return o, Invalid()
		}
	}
	return o, nil
}
func Pair(c access.Credential) (*socks5.Credentials, error) {
	p, ok := c.Payload.(access.UsernamePasswordPayload)
	if !ok {
		return nil, Invalid()
	}
	v := &socks5.Credentials{Username: p.Username.Reveal(), Password: p.Password.Reveal()}
	if v.Validate() != nil || strings.ContainsAny(v.Username, ":\x00\r\n") || strings.ContainsAny(v.Password, "\x00\r\n") {
		return nil, Invalid()
	}
	return v, nil
}
func Validate(protocol string, n client.RemoteNode, c access.Credential) error {
	if clientconfig.Ownership(n, c) != nil || c.Validate() != nil || c.State != "active" || n.Protocol != Key(protocol) || n.Transport.Kind != "tcp" || n.Security.Kind != "none" {
		return Invalid()
	}
	o, e := Decode(n.Options.Data)
	if e != nil || protocol == "http" && o.UDP {
		return Invalid()
	}
	if o.Auth {
		_, e = Pair(c)
		return e
	}
	p, ok := c.Payload.(access.PasswordPayload)
	if !ok || p.Password.Reveal() != NoAuth {
		return Invalid()
	}
	return nil
}
