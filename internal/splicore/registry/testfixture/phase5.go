package testfixture

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	. "github.com/ike-sh/Splicore/internal/splicore/registry"
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
