package application

import (
	"fmt"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

type InboundView struct {
	Inbound   access.Inbound `json:"inbound"`
	BindingID identity.ID    `json:"binding_id,omitempty"`
	AccountID identity.ID    `json:"account_id,omitempty"`
	Health    string         `json:"health"`
	Stats     ports.Stats    `json:"stats"`
	Bindings  []BindingView  `json:"bindings,omitempty"`
}
type InboundPage struct {
	Items    []InboundView     `json:"items"`
	Revision identity.Revision `json:"snapshot_revision"`
}
type ExportRequest struct {
	Format        ports.Format `json:"format"`
	ClientVersion string       `json:"client_version"`
	BindingID     identity.ID  `json:"binding_id,omitempty"`
}
type ExportResult struct {
	Target            ports.Format `json:"format"`
	ClientVersion     string       `json:"client_version"`
	ServerVersion     int          `json:"server_version"`
	ClientWireVersion int          `json:"client_wire_version"`
	Compatibility     string       `json:"compatibility"`
	Content           string       `json:"content"`
	ContentShape      string       `json:"content_shape,omitempty"`
}

func (e ExportResult) Format(f fmt.State, v rune) { _, _ = f.Write([]byte("Export{[REDACTED]}")) }

type DisplayRequest struct {
	Endpoint         access.Endpoint   `json:"endpoint"`
	ResourceRevision identity.Revision `json:"resource_revision"`
	Revision         identity.Revision `json:"revision"`
}
