// Package quiccongestion implements native sender models against the existing
// AperNet QUIC controller interface. It contains no proxy protocol or sockets.
package quiccongestion

import (
	"math"
	"sync"
	"time"

	cc "github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const maxWindow = 64 << 20
const maxHistory = 65536

type Snapshot struct {
	Algorithm               string
	State                   string
	RateBytesPerSecond      uint64
	PacingBytesPerSecond    float64
	BandwidthBytesPerSecond float64
	MinRTT                  time.Duration
	Window                  int64
	Sent, Acked, Lost       uint64
	History                 int
}
type delivery struct {
	sent, firstSent, deliveredTime monotime.Time
	delivered                      uint64
	limited                        bool
}
type sample struct {
	round uint64
	rate  float64
}

// Controller serializes callbacks and diagnostic snapshots. BBR uses the v1
// bandwidth/minimum RTT model and four operating states. Brutal uses a fixed
// application rate, bounded delivery-loss compensation and an RTT flight cap.
type Controller struct {
	mu                               sync.Mutex
	algorithm, state                 string
	rtt                              cc.RTTStatsProvider
	mss, window                      cc.ByteCount
	target, rate, bandwidth          float64
	targetBytes                      uint64
	minRTT                           time.Duration
	measuredRTT                      bool
	minStamp, cycleStamp, probeDone  monotime.Time
	probeRound, round                uint64
	roundEnd, lastSent, recoveryEnd  cc.PacketNumber
	recovery                         bool
	fullBandwidth                    float64
	plateau                          int
	cycle                            int
	filter                           []sample
	history                          map[cc.PacketNumber]delivery
	delivered                        uint64
	deliveryTime, firstSent          monotime.Time
	sentBytes, ackedBytes, lostBytes uint64
	brutalAck, brutalLoss            uint64
	brutalStamp                      monotime.Time
	budget                           float64
	budgetTime                       monotime.Time
}

var _ cc.CongestionControlEx = (*Controller)(nil)

func NewBBR(size cc.ByteCount) *Controller { return newController("bbr", 0, size) }

// rate is bytes/second, strictly positive and already validated by the caller.
func NewBrutal(rate uint64, size cc.ByteCount) *Controller {
	if rate == 0 {
		panic("zero Brutal rate")
	}
	c := newController("brutal", float64(rate), size)
	c.targetBytes = rate
	return c
}
func newController(algorithm string, target float64, size cc.ByteCount) *Controller {
	if size < 1200 {
		size = 1200
	}
	c := &Controller{algorithm: algorithm, state: "STARTUP", mss: size, window: 10 * size,
		target: target, history: make(map[cc.PacketNumber]delivery), budget: float64(10 * size), roundEnd: -1}
	if algorithm == "brutal" {
		c.state = "FIXED_RATE"
		c.rate = target
	} else {
		c.rate = float64(10*size) / .1 * 2.885
	}
	return c
}
func (c *Controller) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Snapshot{c.algorithm, c.state, c.targetBytes, c.rate, c.bandwidth, c.minRTT, int64(c.window), c.sentBytes, c.ackedBytes, c.lostBytes, len(c.history)}
}
func (c *Controller) SetRTTStatsProvider(r cc.RTTStatsProvider) {
	c.mu.Lock()
	c.rtt = r
	c.mu.Unlock()
}
func (c *Controller) replenish(now monotime.Time) {
	if c.budgetTime == 0 {
		c.budgetTime = now
		return
	}
	if now <= c.budgetTime {
		return
	}
	c.budget = math.Min(float64(10*c.mss), c.budget+now.Sub(c.budgetTime).Seconds()*c.rate)
	c.budgetTime = now
}
func (c *Controller) HasPacingBudget(now monotime.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replenish(now)
	return c.budget >= float64(c.mss)
}
func (c *Controller) TimeUntilSend(_ cc.ByteCount) monotime.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := monotime.Now()
	c.replenish(now)
	if c.budget >= float64(c.mss) {
		return 0
	}
	d := time.Duration(math.Ceil((float64(c.mss) - c.budget) / math.Max(1, c.rate) * float64(time.Second)))
	if d < time.Microsecond {
		d = time.Microsecond
	}
	return now.Add(d)
}
func (c *Controller) CanSend(flight cc.ByteCount) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return flight < c.window
}
func (c *Controller) OnPacketSent(now monotime.Time, flight cc.ByteCount, n cc.PacketNumber, size cc.ByteCount, tracked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replenish(now)
	c.budget -= float64(size)
	c.sentBytes += uint64(size)
	if !tracked {
		return
	}
	if c.deliveryTime == 0 {
		c.deliveryTime = now
	}
	if flight == 0 {
		c.firstSent = now
	}
	c.lastSent = n
	if c.algorithm == "bbr" {
		// Saturation of the diagnostic history must never grow memory unboundedly.
		// A missing sample is ignored; QUIC still owns retransmission and ACK state.
		if len(c.history) < maxHistory {
			c.history[n] = delivery{now, c.firstSent, c.deliveryTime, c.delivered, flight+size < c.window}
		}
	}
}
func (c *Controller) OnPacketAcked(n cc.PacketNumber, b, f cc.ByteCount, now monotime.Time) {
	c.OnCongestionEventEx(f, now, []cc.AckedPacketInfo{{PacketNumber: n, BytesAcked: b}}, nil)
}
func (c *Controller) OnCongestionEvent(n cc.PacketNumber, b, f cc.ByteCount) {
	c.OnCongestionEventEx(f, monotime.Now(), nil, []cc.LostPacketInfo{{PacketNumber: n, BytesLost: b}})
}
func (c *Controller) OnCongestionEventEx(flight cc.ByteCount, now monotime.Time, a []cc.AckedPacketInfo, l []cc.LostPacketInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ack, loss cc.ByteCount
	var largest cc.PacketNumber = -1
	for _, p := range a {
		ack += p.BytesAcked
		if p.PacketNumber > largest {
			largest = p.PacketNumber
		}
	}
	for _, p := range l {
		loss += p.BytesLost
		delete(c.history, p.PacketNumber)
	}
	c.ackedBytes += uint64(ack)
	c.lostBytes += uint64(loss)
	if c.algorithm == "brutal" {
		c.brutal(now, ack, loss)
		return
	}
	newRound := largest > c.roundEnd
	if newRound {
		c.round++
		c.roundEnd = c.lastSent
	}
	c.delivered += uint64(ack)
	for _, p := range a {
		s, ok := c.history[p.PacketNumber]
		delete(c.history, p.PacketNumber)
		if !ok {
			continue
		}
		interval := now.Sub(s.deliveredTime)
		if send := s.sent.Sub(s.firstSent); send > interval {
			interval = send
		}
		if interval <= 0 {
			continue
		}
		rate := float64(c.delivered-s.delivered) / interval.Seconds()
		if !s.limited || rate > c.bandwidth {
			c.filter = append(c.filter, sample{c.round, rate})
		}
		// Batch samples collapse into one maximum per round, bounding the filter.
		if len(c.filter) > 1 && c.filter[len(c.filter)-2].round == c.round {
			last := len(c.filter) - 1
			c.filter[last-1].rate = math.Max(c.filter[last-1].rate, c.filter[last].rate)
			c.filter = c.filter[:last]
		}
	}
	if ack > 0 {
		c.deliveryTime = now
	}
	c.bandwidth = 0
	kept := c.filter[:0]
	for _, s := range c.filter {
		if s.round+10 > c.round {
			kept = append(kept, s)
			c.bandwidth = math.Max(c.bandwidth, s.rate)
		}
	}
	c.filter = kept
	rtt := time.Duration(0)
	if c.rtt != nil {
		rtt = c.rtt.LatestRTT()
	}
	if rtt > 0 && (!c.measuredRTT || rtt < c.minRTT) {
		c.minRTT = rtt
		c.measuredRTT = true
		c.minStamp = now
	}
	if c.minRTT == 0 {
		c.minRTT = 100 * time.Millisecond
		c.minStamp = now
	}
	if newRound && c.state == "STARTUP" && c.bandwidth > 0 {
		if c.bandwidth >= c.fullBandwidth*1.25 {
			c.fullBandwidth = c.bandwidth
			c.plateau = 0
		} else {
			c.plateau++
		}
		if c.plateau >= 3 {
			c.state = "DRAIN"
		}
	}
	bdp := c.bandwidth * c.minRTT.Seconds()
	if c.state == "DRAIN" && float64(flight-ack-loss) <= bdp {
		c.state = "PROBE_BW"
		c.cycleStamp = now
		c.cycle = 0
	}
	if c.state != "PROBE_RTT" && now.Sub(c.minStamp) >= 10*time.Second {
		c.state = "PROBE_RTT"
		c.probeDone = 0
		c.probeRound = 0
	}
	if c.state == "PROBE_RTT" {
		if flight-ack-loss <= 4*c.mss && c.probeDone == 0 {
			c.probeDone = now.Add(200 * time.Millisecond)
			c.probeRound = c.round + 1
		}
		if c.probeDone != 0 && now >= c.probeDone && c.round >= c.probeRound {
			if rtt > 0 {
				c.minRTT = rtt
				c.measuredRTT = true
			}
			c.minStamp = now
			c.state = "PROBE_BW"
			c.cycleStamp = now
			c.cycle = 0
		}
	}
	gain := 1.0
	switch c.state {
	case "STARTUP":
		gain = 2.885
	case "DRAIN":
		gain = 1 / 2.885
	case "PROBE_BW":
		if now.Sub(c.cycleStamp) >= c.minRTT {
			c.cycle = (c.cycle + 1) % 8
			c.cycleStamp = now
		}
		gain = []float64{1.25, .75, 1, 1, 1, 1, 1, 1}[c.cycle]
	}
	if c.bandwidth > 0 {
		c.rate = math.Max(float64(c.mss)/c.minRTT.Seconds(), gain*c.bandwidth)
	}
	target := cc.ByteCount(math.Min(maxWindow, math.Max(float64(4*c.mss), 2*bdp+float64(3*c.mss))))
	if c.state == "STARTUP" {
		c.window = min(cc.ByteCount(maxWindow), c.window+ack)
	} else {
		c.window = min(target, c.window+ack)
	}
	if loss > 0 {
		c.recovery = true
		c.recoveryEnd = c.lastSent
		c.window = min(c.window, max(4*c.mss, flight-loss))
	}
	if c.recovery {
		c.window = max(c.window, max(4*c.mss, flight-loss-ack+ack))
		if largest > c.recoveryEnd {
			c.recovery = false
		}
	}
	if c.state == "PROBE_RTT" {
		c.window = 4 * c.mss
	}
	c.window = max(4*c.mss, min(cc.ByteCount(maxWindow), c.window))
}
func (c *Controller) brutal(now monotime.Time, ack, loss cc.ByteCount) {
	c.brutalAck += uint64(ack)
	c.brutalLoss += uint64(loss)
	if c.brutalStamp == 0 {
		c.brutalStamp = now
	}
	// A one-second observation window and minimum packet population prevent
	// one unlucky packet from multiplying the fixed sending rate.
	if now.Sub(c.brutalStamp) >= time.Second && c.brutalAck+c.brutalLoss >= uint64(50*c.mss) {
		fraction := float64(c.brutalAck) / float64(c.brutalAck+c.brutalLoss)
		c.rate = c.target / math.Max(.5, fraction)
		c.brutalAck = 0
		c.brutalLoss = 0
		c.brutalStamp = now
	}
	rtt := 100 * time.Millisecond
	if c.rtt != nil && c.rtt.SmoothedRTT() > 0 {
		rtt = c.rtt.SmoothedRTT()
	}
	c.window = cc.ByteCount(math.Min(maxWindow, math.Max(float64(10*c.mss), 2*c.rate*rtt.Seconds())))
}
func (c *Controller) OnRetransmissionTimeout(retransmitted bool) {
	if !retransmitted {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.history = make(map[cc.PacketNumber]delivery)
	c.recovery = false
	if c.algorithm == "bbr" {
		c.window = 4 * c.mss
		c.state = "STARTUP"
		c.plateau = 0
		c.fullBandwidth = 0
	}
}
func (c *Controller) SetMaxDatagramSize(size cc.ByteCount) {
	if size <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mss = size
	c.window = max(4*size, min(cc.ByteCount(maxWindow), c.window))
	c.budget = math.Min(c.budget, float64(10*size))
}
func (c *Controller) MaybeExitSlowStart() {}
func (c *Controller) InSlowStart() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == "STARTUP"
}
func (c *Controller) InRecovery() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.recovery }
func (c *Controller) GetCongestionWindow() cc.ByteCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.window
}
