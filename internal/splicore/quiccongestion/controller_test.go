package quiccongestion

import (
	cc "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
	"testing"
	"time"
)

type rtt struct{ duration time.Duration }

func (r *rtt) MinRTT() time.Duration         { return r.duration }
func (r *rtt) LatestRTT() time.Duration      { return r.duration }
func (r *rtt) SmoothedRTT() time.Duration    { return r.duration }
func (*rtt) MeanDeviation() time.Duration    { return 0 }
func (*rtt) MaxAckDelay() time.Duration      { return 0 }
func (r *rtt) PTO(bool) time.Duration        { return r.duration * 2 }
func (r *rtt) UpdateRTT(d, _ time.Duration)  { r.duration = d }
func (*rtt) SetMaxAckDelay(time.Duration)    {}
func (r *rtt) SetInitialRTT(d time.Duration) { r.duration = d }

func TestBBRBandwidthStatesProbeRTTAndLoss(t *testing.T) {
	c := NewBBR(1200)
	r := &rtt{100 * time.Millisecond}
	c.SetRTTStatsProvider(r)
	now := monotime.Now()
	n := cc.PacketNumber(0)
	round := func() {
		var a []cc.AckedPacketInfo
		for i := range 10 {
			c.OnPacketSent(now, cc.ByteCount(1200*i), n, 1200, true)
			a = append(a, cc.AckedPacketInfo{PacketNumber: n, BytesAcked: 1200})
			n++
		}
		now = now.Add(100 * time.Millisecond)
		c.OnCongestionEventEx(12000, now, a, nil)
	}
	round()
	if c.Snapshot().BandwidthBytesPerSecond != 120000 {
		t.Fatal(c.Snapshot())
	}
	for range 4 {
		round()
	}
	if c.Snapshot().State != "PROBE_BW" || c.InSlowStart() {
		t.Fatal("startup plateau/drain", c.Snapshot())
	}
	c.OnCongestionEventEx(12000, now, nil, []cc.LostPacketInfo{{PacketNumber: n, BytesLost: 1200}})
	if !c.InRecovery() || c.Snapshot().Lost != 1200 {
		t.Fatal("loss not modeled")
	}
	now = now.Add(11 * time.Second)
	round()
	if c.Snapshot().State != "PROBE_RTT" || c.GetCongestionWindow() != 4800 {
		t.Fatal("RTT refresh", c.Snapshot())
	}
	r.duration = 200 * time.Millisecond
	for range 3 {
		round()
	}
	if c.Snapshot().State != "PROBE_BW" || c.Snapshot().MinRTT != 200*time.Millisecond {
		t.Fatal("probe exit", c.Snapshot())
	}
	c.OnRetransmissionTimeout(true)
	if c.Snapshot().History != 0 || !c.InSlowStart() {
		t.Fatal("timeout reset")
	}
}
func TestDeliverySamplerRejectsACKCompressionAndBoundsHistory(t *testing.T) {
	c := NewBBR(1400)
	now := monotime.Now()
	// Sender spacing is 100ms; an ACK compressed to 1ms cannot claim 2.8MB/s.
	c.OnPacketSent(now, 0, 0, 1400, true)
	c.OnPacketSent(now.Add(100*time.Millisecond), 1400, 1, 1400, true)
	c.OnCongestionEventEx(2800, now.Add(101*time.Millisecond), []cc.AckedPacketInfo{{PacketNumber: 1, BytesAcked: 1400}}, nil)
	if c.Snapshot().BandwidthBytesPerSecond > 14000 {
		t.Fatal("ACK compression", c.Snapshot())
	}
	for i := range maxHistory + 10 {
		c.OnPacketSent(now, 0, cc.PacketNumber(i+2), 1400, true)
	}
	if c.Snapshot().History > maxHistory {
		t.Fatal("unbounded samples")
	}
	c.SetMaxDatagramSize(1500)
	if c.GetCongestionWindow() < 6000 {
		t.Fatal("PMTU floor")
	}
}
func TestBrutalPacingCompensationAndFlightBound(t *testing.T) {
	c := NewBrutal(125000, 1200)
	c.SetRTTStatsProvider(&rtt{100 * time.Millisecond})
	now := monotime.Now()
	for i := range 10 {
		c.OnPacketSent(now, cc.ByteCount(i*1200), cc.PacketNumber(i), 1200, true)
	}
	if c.HasPacingBudget(now) || c.TimeUntilSend(0) == 0 {
		t.Fatal("unpaced fixed rate")
	}
	if !c.HasPacingBudget(now.Add(10 * time.Millisecond)) {
		t.Fatal("token refill")
	}
	c.OnCongestionEventEx(120000, now, []cc.AckedPacketInfo{{BytesAcked: 60000}}, []cc.LostPacketInfo{{BytesLost: 60000}})
	c.OnCongestionEventEx(0, now.Add(time.Second), nil, nil)
	s := c.Snapshot()
	if s.PacingBytesPerSecond != 250000 || s.Window != 50000 {
		t.Fatal("loss compensation", s)
	}
	if c.CanSend(cc.ByteCount(s.Window)) {
		t.Fatal("flight cap ignored")
	}
	big := NewBrutal(125000000000, 1200)
	big.OnCongestionEventEx(0, now, nil, nil)
	if big.GetCongestionWindow() != maxWindow {
		t.Fatal("resource cap")
	}
}
