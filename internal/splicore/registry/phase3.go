package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/internal/splicore/protocol/snell"
)

func Phase3() (*Protocols, *Engines, *Exporters, error) {
	old, _, _, err := Phase2()
	if err != nil {
		return nil, nil, nil, err
	}
	entries := []ports.Protocol{hysteria2.Module{}}
	for _, k := range old.Keys() {
		if k != hysteria2.Key() {
			p, _ := old.Get(k)
			entries = append(entries, p)
		}
	}
	p, err := NewProtocols(entries...)
	if err != nil {
		return nil, nil, nil, err
	}
	nativeEngine, err := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{})
	if err != nil {
		return nil, nil, nil, err
	}
	eng, err := NewEngines(nativeEngine)
	if err != nil {
		return nil, nil, nil, err
	}
	xs := []ports.Exporter{}
	for _, f := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge} {
		protocols := map[access.ProtocolKey]ports.Exporter{snell.Key(5): exporter.Snell{Target: f}, snell.Key(6): exporter.Snell{Target: f}, hysteria2.Key(): exporter.Hysteria2{Target: f}}
		xs = append(xs, exporter.Dispatcher{Target: f, Protocols: protocols})
	}
	xs = append(xs, ExporterPlaceholder{ports.URI}, ExporterPlaceholder{ports.JSON})
	x, err := NewExporters(xs...)
	return p, eng, x, err
}
