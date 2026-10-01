package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"slices"
)

// Implementations declares protocol placement independently of protocol identity.
// Declaration of a future binding does not claim runtime support.
func (r *Engines) Implementations(protocol string) []ports.EngineMetadata {
	out := []ports.EngineMetadata{}
	for _, id := range r.Keys() {
		e, _ := r.Get(id)
		m := e.Metadata()
		if slices.Contains(m.Protocols, protocol) {
			m.Protocols = slices.Clone(m.Protocols)
			out = append(out, m)
		}
	}
	return out
}
