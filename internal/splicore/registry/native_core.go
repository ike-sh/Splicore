package registry

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
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
	protocols = append(protocols, mieru.Module{}, shadowsocks.Module{Edition: "2017"}, shadowsocks.Module{Edition: "2022"})
	p, e = NewProtocols(protocols...)
	if e != nil {
		return nil, nil, nil, e
	}
	n, e := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{}, native.TUICCompiler{}, native.VLESSCompiler{}, native.MieruCompiler{}, native.NewShadowsocksCompiler())
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
	for n, entry := range entries {
		d, ok := entry.(exporter.Dispatcher)
		if !ok || d.Target != ports.URI && d.Target != ports.Mihomo && d.Target != ports.SingBox {
			continue
		}
		mapping := map[access.ProtocolKey]ports.Exporter{}
		for k, v := range d.Protocols {
			mapping[k] = v
		}
		for _, edition := range []string{"2017", "2022"} {
			mapping[shadowsocks.Key(edition)] = exporter.Shadowsocks{Target: d.Target}
		}
		d.Protocols = mapping
		entries[n] = d
	}
	entries = append(entries, exporter.Dispatcher{Target: ports.Mieru, Protocols: map[access.ProtocolKey]ports.Exporter{mieru.Key(): exporter.Mieru{Target: ports.Mieru}}})
	entries = append(entries, exporter.Dispatcher{Target: ports.Xray, Protocols: map[access.ProtocolKey]ports.Exporter{vless.Key(vless.Plain): exporter.VLESS{Target: ports.Xray}}})
	exports, e = NewExporters(entries...)
	return p, engines, exports, e
}
