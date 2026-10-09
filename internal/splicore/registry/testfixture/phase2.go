package testfixture

import (
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	. "github.com/ike-sh/Splicore/internal/splicore/registry"
)

func Phase2() (*Protocols, *Engines, *Exporters, error) {
	old, _, _, e := Foundation()
	if e != nil {
		return nil, nil, nil, e
	}
	entries := []ports.Protocol{snell.Module{Version: 5}, snell.Module{Version: 6}}
	for _, k := range old.Keys() {
		if k.Protocol != "snell" {
			p, _ := old.Get(k)
			entries = append(entries, p)
		}
	}
	p, e := NewProtocols(entries...)
	if e != nil {
		return nil, nil, nil, e
	}
	eng, e := NewEngines(native.Engine{})
	if e != nil {
		return nil, nil, nil, e
	}
	x, e := NewExporters(exporter.Snell{Target: ports.Mihomo}, exporter.Snell{Target: ports.SingBox}, exporter.Snell{Target: ports.Surge}, ExporterPlaceholder{ports.URI}, ExporterPlaceholder{ports.JSON})
	return p, eng, x, e
}
