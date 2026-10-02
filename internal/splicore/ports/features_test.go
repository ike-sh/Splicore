package ports

import "testing"

func TestFeatureCompositionScopeAndOwnedSnapshots(t *testing.T) {
	p := EngineFeature{ID: "sudoku", Supported: true, Transport: "tcp", Security: "none", Flow: "none", Clients: []FeatureClient{{Client: "xray", Version: "26.3.27", Support: "supported"}}}
	e := p
	e.Clients = append([]FeatureClient(nil), p.Clients...)
	r := EffectiveCapabilities(Capabilities{EngineFeatures: []EngineFeature{p}}, Capabilities{EngineFeatures: []EngineFeature{e}})
	if !r.EngineFeatures[0].Supported || r.EngineFeatures[0].UDPQualified {
		t.Fatal("feature scope")
	}
	r.EngineFeatures[0].Clients[0].Version = "changed"
	if p.Clients[0].Version != "26.3.27" || e.Clients[0].Version != "26.3.27" {
		t.Fatal("snapshot aliases input")
	}
	for _, change := range []func(*EngineFeature){func(f *EngineFeature) { f.Security = "reality" }, func(f *EngineFeature) { f.Flow = "xtls-rprx-vision" }, func(f *EngineFeature) { f.Supported = false }, func(f *EngineFeature) { f.ID = "unknown" }} {
		modified := e
		change(&modified)
		r = EffectiveCapabilities(Capabilities{EngineFeatures: []EngineFeature{p}}, Capabilities{EngineFeatures: []EngineFeature{modified}})
		if r.EngineFeatures[0].Supported || r.EngineFeatures[0].Clients[0].Support != "unsupported" {
			t.Fatal("incompatible feature composed")
		}
	}
	e.Clients[0].Support = "unknown"
	r = EffectiveCapabilities(Capabilities{EngineFeatures: []EngineFeature{p}}, Capabilities{EngineFeatures: []EngineFeature{e}})
	if r.EngineFeatures[0].Clients[0].Support != "unsupported" {
		t.Fatal("unknown client support overclaim")
	}
}
