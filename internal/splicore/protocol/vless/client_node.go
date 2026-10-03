package vless

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
)

// ValidateClientNode shares canonical flow/options validation with projections;
// server settings and server secret repositories are never part of this path.
func ValidateClientNode(n client.RemoteNode, c access.Credential) error {
	if err := n.Validate(); err != nil {
		return err
	}
	o, err := DecodeClientOptions(n.Options.Data)
	if err != nil {
		return err
	}
	if n.Protocol != Key(o.Security) || n.Transport.Kind != "tcp" || n.Security.Kind != string(o.Security) || c.OwnerNodeID == nil || *c.OwnerNodeID != n.ID || c.ID != n.CredentialID {
		return invalid()
	}
	if o.Security == Reality {
		if ValidatePublicKey(PublicKey(n.Security.TLS.RealityPublicKey)) != nil {
			return invalid()
		}
		if _, err := ParseShortID(ShortID(n.Security.TLS.RealityShortID)); err != nil {
			return err
		}
	}
	return (Module{Security: o.Security}).ValidateCredential(c)
}
