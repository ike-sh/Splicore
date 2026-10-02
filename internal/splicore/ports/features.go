package ports

import "slices"

type FeatureClient struct {
	Client  string `json:"client"`
	Version string `json:"version,omitempty"`
	Support string `json:"support"`
}
type EngineFeature struct {
	ID           string          `json:"id"`
	Supported    bool            `json:"supported"`
	Transport    string          `json:"transport"`
	Security     string          `json:"security"`
	Flow         string          `json:"flow"`
	UDPQualified bool            `json:"udp_qualified"`
	Clients      []FeatureClient `json:"clients"`
}
type FeatureAvailability struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func CloneFeatures(features []EngineFeature) []EngineFeature {
	result := slices.Clone(features)
	for n := range result {
		result[n].Clients = slices.Clone(result[n].Clients)
	}
	return result
}
func intersectFeatures(protocol, engine []EngineFeature) []EngineFeature {
	result := CloneFeatures(protocol)
	for n := range result {
		result[n].Supported = false
		result[n].UDPQualified = false
		for _, e := range engine {
			p := protocol[n]
			if p.ID == e.ID && p.Transport == e.Transport && p.Security == e.Security && p.Flow == e.Flow {
				result[n].Supported = p.Supported && e.Supported
				result[n].UDPQualified = result[n].Supported && p.UDPQualified && e.UDPQualified
				for i := range result[n].Clients {
					result[n].Clients[i].Support = "unsupported"
					for _, c := range e.Clients {
						if p.Clients[i].Client == c.Client && p.Clients[i].Version == c.Version && p.Clients[i].Support == "supported" && c.Support == "supported" && result[n].Supported {
							result[n].Clients[i].Support = "supported"
						}
					}
				}
			}
		}
		if !result[n].Supported {
			for i := range result[n].Clients {
				result[n].Clients[i].Support = "unsupported"
			}
		}
	}
	return result
}
