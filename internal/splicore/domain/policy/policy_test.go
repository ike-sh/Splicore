package policy

import (
	"testing"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

func TestNullableLimits(t *testing.T) {
	id, _ := identity.NewID()
	p := TrafficPolicy{ID: id, Stamp: identity.NewStamp(time.Now())}
	if p.Validate() != nil {
		t.Fatal("unlimited policy rejected")
	}
	zero := int64(0)
	p.QuotaBytes = &zero
	if p.Validate() != nil {
		t.Fatal("zero denial rejected")
	}
	negative := int64(-1)
	p.UploadBps = &negative
	if p.Validate() == nil {
		t.Fatal("negative rate accepted")
	}
	p.UploadBps = nil
	p.ResetPolicy = &ResetPolicy{Kind: "daily", Timezone: "UTC"}
	if p.Validate() != nil {
		t.Fatal("UTC reset rejected")
	}
	p.ResetPolicy.Timezone = "invalid-zone"
	if p.Validate() == nil {
		t.Fatal("invalid timezone accepted")
	}
}
