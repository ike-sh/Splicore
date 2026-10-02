package registry

import "github.com/sagernet/sing-box/internal/splicore/ports"

// Phase6 fills the existing xray placement; historical composition stays usable.
func Phase6(xray ports.Engine) (*Protocols, *Engines, *Exporters, error) {
	p, engines, exports, err := Phase5()
	if err != nil {
		return nil, nil, nil, err
	}
	native, _ := engines.Get("native")
	engines, err = NewEngines(native, xray)
	return p, engines, exports, err
}
