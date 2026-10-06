package registry

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
)

func Phase4() (*Protocols, *Engines, *Exporters, error) {
	entries := []ports.Protocol{snell.Module{Version: 5}, snell.Module{Version: 6}, hysteria2.Module{}, tuic.Module{}, ProtocolPlaceholder{ports.ProtocolMetadata{Key: access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: "base"}, ABI: 1, CredentialKinds: []access.CredentialKind{access.UUID}, Availability: ports.NotCompiled, Qualification: "unqualified", Provenance: "sing-box v1.14.1; adapter deferred"}}}
	p, err := NewProtocols(entries...)
	if err != nil {
		return nil, nil, nil, err
	}
	nativeEngine, err := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{}, native.TUICCompiler{})
	if err != nil {
		return nil, nil, nil, err
	}
	eng, err := NewEngines(nativeEngine)
	if err != nil {
		return nil, nil, nil, err
	}
	xs := []ports.Exporter{}
	for _, f := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge} {
		protocols := map[access.ProtocolKey]ports.Exporter{snell.Key(5): exporter.Snell{Target: f}, snell.Key(6): exporter.Snell{Target: f}, hysteria2.Key(): exporter.Hysteria2{Target: f}, tuic.Key(): exporter.TUIC{Target: f}}
		xs = append(xs, exporter.Dispatcher{Target: f, Protocols: protocols})
	}
	xs = append(xs, ExporterPlaceholder{ports.URI}, ExporterPlaceholder{ports.JSON})
	x, err := NewExporters(xs...)
	return p, eng, x, err
}
