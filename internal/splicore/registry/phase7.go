package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

// Phase7 adds one client format; protocol identities, engines and supervisors
// remain the Phase6 composition. Export dispatch depends on protocol, not engine.
func Phase7(xray ports.Engine) (*Protocols, *Engines, *Exporters, error) {
	p, engines, exports, err := Phase6(xray)
	if err != nil {
		return nil, nil, nil, err
	}
	entries := []ports.Exporter{}
	for _, format := range exports.Keys() {
		e, _ := exports.Get(format)
		entries = append(entries, e)
	}
	entries = append(entries, exporter.Dispatcher{Target: ports.Xray, Protocols: map[access.ProtocolKey]ports.Exporter{
		vless.Key(vless.Plain): exporter.VLESS{Target: ports.Xray},
	}})
	exports, err = NewExporters(entries...)
	return p, engines, exports, err
}
