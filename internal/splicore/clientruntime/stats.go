package clientruntime

import (
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"strconv"
)

// Sessions counts TCP streams. UDP has separate association and packet counts.
// Upload/Download are application payload bytes in either transport. These are
// projections at each dimension, never values to sum across dimensions.
type TrafficStats struct {
	ports.Stats
	UDPAssociations int64
	UDPActive       int64
	PacketsUpload   int64
	PacketsDownload int64
}

func (s *TrafficStats) UnmarshalJSON(b []byte) error {
	var fields map[string]string
	if json.Unmarshal(b, &fields) != nil {
		return identity.Err(identity.Invalid, "invalid client stats")
	}
	targets := map[string]*int64{"upload_bytes": &s.Upload, "download_bytes": &s.Download, "sessions_total": &s.Sessions, "sessions_active": &s.Active, "udp_associations_total": &s.UDPAssociations, "udp_associations_active": &s.UDPActive, "udp_packets_upload": &s.PacketsUpload, "udp_packets_download": &s.PacketsDownload}
	for name, target := range targets {
		value, ok := fields[name]
		if !ok {
			return identity.Err(identity.Invalid, "missing client stats counter")
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return identity.Err(identity.Invalid, "invalid client stats counter")
		}
		*target = n
	}
	return nil
}

func (s TrafficStats) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"upload_bytes": strconv.FormatInt(s.Upload, 10), "download_bytes": strconv.FormatInt(s.Download, 10),
		"sessions_total": strconv.FormatInt(s.Sessions, 10), "sessions_active": strconv.FormatInt(s.Active, 10),
		"udp_associations_total": strconv.FormatInt(s.UDPAssociations, 10), "udp_associations_active": strconv.FormatInt(s.UDPActive, 10),
		"udp_packets_upload": strconv.FormatInt(s.PacketsUpload, 10), "udp_packets_download": strconv.FormatInt(s.PacketsDownload, 10),
	})
}
