package streamtransport

import (
	"bytes"
	"encoding/json"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
)

var ErrLegacyMKCP = identity.Err(identity.Invalid, "modern mKCP rejects legacy header/seed; FinalMask mkcp-legacy is not implemented")

// MKCP contains local transport tuning, never account or protocol credentials.
// Capacity units follow the compatible peer's binary MB/s arithmetic (MiB/s).
type MKCP struct {
	MTU              uint32 `json:"mtu"`
	TTI              uint32 `json:"tti"`
	UplinkCapacity   uint32 `json:"uplinkCapacity"`
	DownlinkCapacity uint32 `json:"downlinkCapacity"`
	CWNDMultiplier   uint32 `json:"cwndMultiplier"`
	MaxSendingWindow uint32 `json:"maxSendingWindow"`
}

func DefaultMKCP() MKCP {
	return MKCP{MTU: 1350, TTI: 50, UplinkCapacity: 5, DownlinkCapacity: 20, CWNDMultiplier: 1, MaxSendingWindow: 2 << 20}
}

func (m *MKCP) UnmarshalJSON(b []byte) error {
	var fields map[string]json.RawMessage
	if len(b) > 2048 || jsonstrict.Decode(b, &fields) != nil || fields == nil {
		return bad()
	}
	allowed := map[string]bool{"mtu": true, "tti": true, "uplinkCapacity": true, "downlinkCapacity": true, "cwndMultiplier": true, "maxSendingWindow": true}
	for k, v := range fields {
		if k == "header" || k == "seed" {
			return ErrLegacyMKCP
		}
		if !allowed[k] || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return bad()
		}
	}
	type plain MKCP
	p := plain(DefaultMKCP())
	if jsonstrict.Decode(b, &p) != nil {
		return bad()
	}
	if MKCP(p).Validate() != nil {
		return bad()
	}
	*m = MKCP(p)
	return nil
}

func (m MKCP) Validate() error {
	if m.MTU < 576 || m.MTU > 1460 || m.TTI < 10 || m.TTI > 100 || m.UplinkCapacity > 4095 || m.DownlinkCapacity > 4095 || m.CWNDMultiplier < 1 || m.CWNDMultiplier > 1024 || m.MaxSendingWindow < m.MTU || m.MaxSendingWindow > 16<<20 {
		return bad()
	}
	// Receive peers may use a different (valid) MTU. Reserve against that bound.
	if uint64(m.ReceiveSlots())*1460 > 16<<20 {
		return bad()
	}
	return nil
}

func (m MKCP) intervalSlots(capacity uint32) uint32 {
	if m.MTU == 0 || m.TTI == 0 || m.TTI > 1000 {
		return 0
	}
	n := uint64(capacity) * (1 << 20) / uint64(m.MTU) / uint64(1000/m.TTI)
	if n < 8 {
		n = 8
	}
	return uint32(n)
}
func (m MKCP) SendSlots() uint32    { return m.intervalSlots(m.UplinkCapacity) }
func (m MKCP) ReceiveSlots() uint32 { return m.intervalSlots(m.DownlinkCapacity) }
func (m MKCP) QueueSlots() uint32 {
	if m.MTU == 0 {
		return 0
	}
	return m.MaxSendingWindow / m.MTU
}
func (m MKCP) PayloadBound() uint64 {
	// Include the independent transmit snapshot and one partially read segment.
	return 2*uint64(m.QueueSlots())*uint64(m.MTU) + uint64(m.ReceiveSlots())*1460 + 1460
}
func (c Config) MKCPSettings() MKCP {
	if c.MKCP != nil {
		return *c.MKCP
	}
	return DefaultMKCP()
}

// Carrier names the owned listening socket independently of upper byte streams.
func (c Config) Carrier() string {
	if c.Type() == "mkcp" {
		return "udp"
	}
	return "tcp"
}
