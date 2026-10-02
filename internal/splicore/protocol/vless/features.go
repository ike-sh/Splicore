package vless

import "github.com/sagernet/sing-box/internal/splicore/ports"

// TransportFeatures describes the bounded qualified combination, not the
// complete set of upstream masks, transports or TLS combinations.
func TransportFeatures(supported bool) []ports.EngineFeature {
	result := []ports.EngineFeature{}
	for _, id := range []string{"finalmask", "sudoku"} {
		result = append(result, ports.EngineFeature{ID: id, Supported: supported,
			Transport: "tcp", Security: "none", Flow: "none", UDPQualified: false,
			Clients: []ports.FeatureClient{{Client: "xray", Version: "26.3.27", Support: "supported"},
				{Client: "mihomo", Version: "1.19.30", Support: "unsupported"},
				{Client: "sing-box", Version: "1.14.1", Support: "unsupported"},
				{Client: "surge", Support: "unsupported"}, {Client: "uri", Support: "unsupported"}}})
		if !supported {
			for n := range result[len(result)-1].Clients {
				result[len(result)-1].Clients[n].Support = "unsupported"
			}
		}
	}
	return result
}
