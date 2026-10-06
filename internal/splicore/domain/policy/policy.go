// Package policy defines future enforcement contracts, without implementing traffic control.
package policy

import (
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

type ResetPolicy struct {
	Kind     string `json:"kind"`
	Timezone string `json:"timezone"`
}
type TrafficPolicy struct {
	ID          identity.ID  `json:"id"`
	QuotaBytes  *int64       `json:"quota_bytes,omitempty"`
	UploadBps   *int64       `json:"upload_bps,omitempty"`
	DownloadBps *int64       `json:"download_bps,omitempty"`
	ResetPolicy *ResetPolicy `json:"reset_policy,omitempty"`
	MaxSessions *int64       `json:"max_sessions,omitempty"`
	identity.Stamp
}

func (p TrafficPolicy) Validate() error {
	if err := p.ID.Validate(); err != nil {
		return err
	}
	for _, n := range []*int64{p.QuotaBytes, p.UploadBps, p.DownloadBps, p.MaxSessions} {
		if n != nil && *n < 0 {
			return identity.Err(identity.Invalid, "negative policy limit")
		}
	}
	if p.ResetPolicy != nil {
		if p.ResetPolicy.Kind != "none" && p.ResetPolicy.Kind != "daily" && p.ResetPolicy.Kind != "monthly" {
			return identity.Err(identity.Invalid, "invalid reset policy")
		}
		if _, err := time.LoadLocation(p.ResetPolicy.Timezone); err != nil {
			return identity.Err(identity.Invalid, "invalid reset timezone")
		}
	}
	return p.Stamp.Validate()
}
