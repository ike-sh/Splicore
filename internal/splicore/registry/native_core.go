package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/mieru"
	"github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

func NativeCore() (*Protocols, *Engines, *Exporters, error) {
	p, _, exports, e := Phase5()
	if e != nil {
		return nil, nil, nil, e
	}
	protocols := []ports.Protocol{}
	for _, key := range p.Keys() {
		entry, _ := p.Get(key)
		protocols = append(protocols, entry)
	}
	protocols = append(protocols, mieru.Module{})
	p, e = NewProtocols(protocols...)
	if e != nil {
		return nil, nil, nil, e
	}
	n, e := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{}, native.TUICCompiler{}, native.VLESSCompiler{}, native.MieruCompiler{})
	if e != nil {
		return nil, nil, nil, e
	}
	engines, e := NewEngines(n)
	if e != nil {
		return nil, nil, nil, e
	}
	entries := []ports.Exporter{}
	for _, format := range exports.Keys() {
		entry, _ := exports.Get(format)
		if format == ports.Mihomo {
			old := entry.(exporter.Dispatcher)
			mapping := map[access.ProtocolKey]ports.Exporter{}
			for k, v := range old.Protocols {
				mapping[k] = v
			}
			mapping[mieru.Key()] = exporter.Mieru{Target: format}
			entry = exporter.Dispatcher{Target: format, Protocols: mapping}
		}
		entries = append(entries, entry)
	}
	entries = append(entries, exporter.Dispatcher{Target: ports.Mieru, Protocols: map[access.ProtocolKey]ports.Exporter{mieru.Key(): exporter.Mieru{Target: ports.Mieru}}})
	entries = append(entries, exporter.Dispatcher{Target: ports.Xray, Protocols: map[access.ProtocolKey]ports.Exporter{vless.Key(vless.Plain): exporter.VLESS{Target: ports.Xray}}})
	exports, e = NewExporters(entries...)
	return p, engines, exports, e
}
