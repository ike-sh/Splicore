package hysteria

import (
	"strconv"

	"github.com/apernet/quic-go"
	cc "github.com/apernet/quic-go/congestion"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/quiccongestion"
)

type CongestionState struct {
	Identity                    string
	Requested                   string
	PeerAdvertisement           string
	Selected                    string
	EffectiveRateBytesPerSecond uint64
	Controller                  string
	Model                       quiccongestion.Snapshot
}

// Receive advertisements and sender rates are relative to the local endpoint.
// A client advertises its Down. A server advertises its Down (client upload).
func receiveRate(q cfg.QUIC, server bool) string {
	q = q.Defaults()
	if q.Congestion == "reno" || q.Congestion == "bbr" {
		if server {
			return "auto"
		}
		return "0"
	}
	n, _ := cfg.RateBytes(q.BrutalDown)
	return strconv.FormatUint(n, 10)
}
func chooseCongestion(q cfg.QUIC, peer string, server bool) (CongestionState, error) {
	q = q.Defaults()
	n, auto, e := CCRX(peer, !server)
	if e != nil {
		return CongestionState{}, e
	}
	s := CongestionState{Requested: q.Congestion, PeerAdvertisement: peer, Selected: q.Congestion, Controller: "library Reno"}
	up, _ := cfg.RateBytes(q.BrutalUp)
	switch q.Congestion {
	case "brutal":
		if server {
			// Server TX is requested by client RX, capped by server Up.
			if n > 0 {
				if up > 0 {
					n = min(n, up)
				}
				s.EffectiveRateBytesPerSecond = n
			} else {
				s.Selected = "bbr"
			}
		} else {
			// Numeric server RX=0 means unlimited; auto requests adaptation.
			if !auto && up > 0 {
				if n > 0 {
					up = min(up, n)
				}
				s.EffectiveRateBytesPerSecond = up
			} else {
				s.Selected = "bbr"
			}
		}
	case "force-brutal":
		s.Selected = "brutal"
		s.EffectiveRateBytesPerSecond = up
	}
	if s.Selected != "reno" {
		s.Controller = "native " + s.Selected
	}
	return s, nil
}
func installCongestion(q *quic.Conn, s CongestionState) *quiccongestion.Controller {
	var c *quiccongestion.Controller
	switch s.Selected {
	case "bbr":
		c = quiccongestion.NewBBR(cc.ByteCount(q.InitialPacketSize()))
	case "brutal":
		c = quiccongestion.NewBrutal(s.EffectiveRateBytesPerSecond, cc.ByteCount(q.InitialPacketSize()))
	}
	if c != nil {
		q.SetCongestionControl(c)
	}
	return c
}
func (c *Connection) Congestion() CongestionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.congestion
	s.Identity = c.Identity()
	if c.controller != nil {
		s.Model = c.controller.Snapshot()
	}
	return s
}
