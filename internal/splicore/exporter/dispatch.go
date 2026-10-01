package exporter

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/clientprofile"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
)

// Dispatcher is a format registry over protocol keys; unsupported keys fail closed.
type Dispatcher struct {
	Target    ports.Format
	Protocols map[access.ProtocolKey]ports.Exporter
}

func (e Dispatcher) Format() ports.Format { return e.Target }
func (e Dispatcher) Export(ctx context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	x := e.Protocols[p.Protocol]
	if x == nil {
		return nil, unsupported()
	}
	return x.Export(ctx, p, t)
}
func (e Dispatcher) Describe(p clientprofile.Profile) (ports.ExportDescription, error) {
	x, ok := e.Protocols[p.Protocol].(ports.ExportDescriber)
	if !ok {
		return ports.ExportDescription{}, unsupported()
	}
	return x.Describe(p)
}
