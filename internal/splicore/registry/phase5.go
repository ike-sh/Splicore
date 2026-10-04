package registry

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/engine/native"
	"github.com/sagernet/sing-box/internal/splicore/exporter"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/internal/splicore/protocol/snell"
	"github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

func Phase5() (*Protocols, *Engines, *Exporters, error) {
	p, err := NewProtocols(snell.Module{Version: 5}, snell.Module{Version: 6}, hysteria2.Module{}, tuic.Module{}, vless.Module{Security: vless.Plain}, vless.Module{Security: vless.TLS}, vless.Module{Security: vless.Reality})
	if err != nil {
		return nil, nil, nil, err
	}
	n, err := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{}, native.TUICCompiler{}, native.VLESSCompiler{})
	if err != nil {
		return nil, nil, nil, err
	}
	e, err := NewEngines(n)
	if err != nil {
		return nil, nil, nil, err
	}
	xs := []ports.Exporter{}
	for _, format := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge, ports.URI} {
		entries := map[access.ProtocolKey]ports.Exporter{}
		if format != ports.URI {
			entries[snell.Key(5)] = exporter.Snell{Target: format}
			entries[snell.Key(6)] = exporter.Snell{Target: format}
			entries[hysteria2.Key()] = exporter.Hysteria2{Target: format}
			entries[tuic.Key()] = exporter.TUIC{Target: format}
		}
		for _, security := range []vless.Security{vless.Plain, vless.TLS, vless.Reality} {
			entries[vless.Key(security)] = exporter.VLESS{Target: format}
		}
		xs = append(xs, exporter.Dispatcher{Target: format, Protocols: entries})
	}
	xs = append(xs, ExporterPlaceholder{ID: ports.JSON})
	x, err := NewExporters(xs...)
	return p, e, x, err
}
