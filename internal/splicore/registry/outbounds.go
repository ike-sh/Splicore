package registry

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"sort"
)

type outboundKey struct{ protocol, engine string }

// Outbounds is immutable after construction, just like Protocols and Engines.
type Outbounds struct {
	factories map[outboundKey]ports.OutboundFactory
}

func NewOutbounds(entries ...ports.OutboundFactory) (*Outbounds, error) {
	r := &Outbounds{factories: map[outboundKey]ports.OutboundFactory{}}
	for _, f := range entries {
		if nilEntry(f) {
			return nil, identity.Err(identity.Invalid, "nil outbound factory")
		}
		c := f.Capability()
		k := outboundKey{c.Protocol, c.Engine}
		if !identity.Label(c.Protocol, 64) || !identity.Label(c.Engine, 64) || r.factories[k] != nil {
			return nil, identity.Err(identity.Invalid, "invalid or duplicate outbound factory")
		}
		r.factories[k] = f
	}
	return r, nil
}
func (r *Outbounds) Get(protocol, engine string) (ports.OutboundFactory, error) {
	f := r.factories[outboundKey{protocol, engine}]
	if f == nil {
		return nil, identity.Err(identity.UnsupportedEngineForProtocol, "outbound protocol/engine pair is unavailable")
	}
	return f, nil
}
func (r *Outbounds) Capabilities() []ports.OutboundCapability {
	out := []ports.OutboundCapability{}
	for _, f := range r.factories {
		out = append(out, f.Capability())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Protocol+out[i].Engine < out[j].Protocol+out[j].Engine })
	return out
}
