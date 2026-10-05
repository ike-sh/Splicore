package ports

import "github.com/sagernet/sing-box/internal/splicore/clientprofile"

// Export descriptions belong to client contracts, not the application coordinator.
type ExportDescription struct {
	ServerVersion     int
	ClientWireVersion int
	Compatibility     string
	ContentShape      string
}
type ExportDescriber interface {
	Describe(clientprofile.Profile) (ExportDescription, error)
}
