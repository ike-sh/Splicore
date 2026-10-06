package registry

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// Creation is an optional protocol-owned command port. Multiple wire versions
// share one decoder, which validates and selects the document's exact key.
func (p *Protocols) Creation(id string) (ports.CreationCodec, error) {
	for _, k := range p.Keys() {
		if k.Protocol == id {
			v, _ := p.Get(k)
			if v.Metadata().Availability != ports.Compiled {
				continue
			}
			if c, ok := v.(ports.CreationCodec); ok {
				return c, nil
			}
		}
	}
	return nil, identity.Err(identity.NotImplemented, "creation command unavailable")
}
