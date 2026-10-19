package exporter

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trusttunnel"
)

type TrustTunnel struct{ Target ports.Format }

func (e TrustTunnel) Format() ports.Format { return e.Target }
func (e TrustTunnel) Describe(clientprofile.Profile) (ports.ExportDescription, error) {
	return ports.ExportDescription{Compatibility: "TrustTunnel static deep-link v0–2 import, v1 export; optional app/DNS/TLS extensions not admitted", ContentShape: "trusttunnel-deeplink"}, nil
}
func (e TrustTunnel) Export(_ context.Context, p clientprofile.Profile, t ports.ExportTarget) ([]byte, error) {
	if e.Target != ports.URI || t.Format != ports.URI || t.ClientVersion != "" {
		return nil, unsupported()
	}
	s, err := module.ExportLink(p)
	return []byte(s), err
}
