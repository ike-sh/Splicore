package exporter

import (
	"context"
	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

// UnsupportedFormat retains an existing frozen format's typed rejection.
type UnsupportedFormat struct{ Target ports.Format }

func (e UnsupportedFormat) Format() ports.Format { return e.Target }
func (e UnsupportedFormat) Export(context.Context, clientprofile.Profile, ports.ExportTarget) ([]byte, error) {
	return nil, identity.Err(identity.NotImplemented, "export format is unsupported")
}
