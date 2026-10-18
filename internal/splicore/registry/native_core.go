package registry

import (
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/engine/native"
	"github.com/ike-sh/Splicore/internal/splicore/exporter"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/anytls"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/mieru"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/naive"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/tuic"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/vmess"
)

func NativeCore() (*Protocols, *Engines, *Exporters, error) {
	protocols := []ports.Protocol{snell.Module{Version: 4}, snell.Module{Version: 5}, snell.Module{Version: 6}, hysteria2.Module{}, tuic.Module{}, vless.Module{Security: vless.Plain}, vless.Module{Security: vless.TLS}, vless.Module{Security: vless.Reality}}
	protocols = append(protocols, mieru.Module{}, shadowsocks.Module{Edition: "2017"}, shadowsocks.Module{Edition: "2022"}, trojan.Module{}, vmess.Module{}, anytls.Module{}, naive.Module{})
	p, e := NewProtocols(protocols...)
	if e != nil {
		return nil, nil, nil, e
	}
	n, e := native.NewEngine(native.SnellCompiler{}, native.Hysteria2Compiler{}, native.TUICCompiler{}, native.VLESSCompiler{}, native.MieruCompiler{}, native.NewShadowsocksCompiler(), native.TrojanCompiler{}, native.NewVMessCompiler(), native.AnyTLSCompiler{}, native.NaiveCompiler{})
	if e != nil {
		return nil, nil, nil, e
	}
	engines, e := NewEngines(n)
	if e != nil {
		return nil, nil, nil, e
	}
	entries := []ports.Exporter{}
	for _, format := range []ports.Format{ports.Mihomo, ports.SingBox, ports.Surge, ports.URI} {
		mapping := map[access.ProtocolKey]ports.Exporter{}
		if format != ports.URI {
			mapping[snell.Key(4)] = exporter.Snell{Target: format}
			mapping[snell.Key(5)] = exporter.Snell{Target: format}
			mapping[snell.Key(6)] = exporter.Snell{Target: format}
			mapping[hysteria2.Key()] = exporter.Hysteria2{Target: format}
			mapping[tuic.Key()] = exporter.TUIC{Target: format}
		}
		for _, security := range []vless.Security{vless.Plain, vless.TLS, vless.Reality} {
			mapping[vless.Key(security)] = exporter.VLESS{Target: format}
		}
		if format == ports.Mihomo {
			mapping[mieru.Key()] = exporter.Mieru{Target: format}
		}
		entries = append(entries, exporter.Dispatcher{Target: format, Protocols: mapping})
	}
	// Frozen format identity retains its existing typed unsupported contract.
	entries = append(entries, exporter.UnsupportedFormat{Target: ports.JSON})
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
		mapping[trojan.Key()] = exporter.Trojan{Target: d.Target}
		mapping[vmess.Key()] = exporter.VMess{Target: d.Target}
		if d.Target == ports.URI || d.Target == ports.SingBox {
			mapping[anytls.Key()] = exporter.AnyTLS{Target: d.Target}
		}
		if d.Target == ports.URI {
			mapping[hysteria2.Key()] = exporter.Hysteria2{Target: d.Target}
			mapping[naive.Key()] = exporter.Naive{Target: d.Target}
		}
		mapping[proxy.Key("socks5")] = exporter.Proxy{Target: d.Target}
		mapping[proxy.Key("http")] = exporter.Proxy{Target: d.Target}
		d.Protocols = mapping
		entries[n] = d
	}
	entries = append(entries, exporter.Dispatcher{Target: ports.Mieru, Protocols: map[access.ProtocolKey]ports.Exporter{mieru.Key(): exporter.Mieru{Target: ports.Mieru}}})
	entries = append(entries, exporter.Dispatcher{Target: ports.Xray, Protocols: map[access.ProtocolKey]ports.Exporter{vless.Key(vless.Plain): exporter.VLESS{Target: ports.Xray}}})
	exports, e := NewExporters(entries...)
	return p, engines, exports, e
}
