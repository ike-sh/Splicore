package encryption

import "time"

const (
	maxPaddingTuples = 31
	maxPaddingGapMS  = 1000
	// The existing active budget covers crypto, IO and account admission. The
	// pinned reference finishes Encryption before starting its VLESS timer.
	activeHandshakeBudget = 5 * time.Second
	// Remote padding is independently configured and not negotiated. Reserve
	// the entire supported peer scope, never a peer-supplied duration.
	peerPaddingBudget = (maxPaddingTuples / 2) * maxPaddingGapMS * time.Millisecond
)

func (c *Config) paddingTuples() []tuple {
	if len(c.padding) == 0 {
		return []tuple{{100, 111, 1111}, {75, 0, 111}, {50, 0, 3333}}
	}
	return c.padding
}

// PaddingDelayBounds returns exact possible cumulative local sleep bounds.
// RandBetween excludes its upper endpoint except for a fixed range. Selection
// compares probability >= a sample in [0,100), so even probability 99 is certain.
func (c *Config) PaddingDelayBounds() (minimum, maximum time.Duration) {
	for n, t := range c.paddingTuples() {
		if n%2 == 0 {
			continue
		}
		high := t.high
		if high > t.low {
			high--
		}
		maximum += time.Duration(high) * time.Millisecond
		if t.probability >= 99 {
			minimum += time.Duration(t.low) * time.Millisecond
		}
	}
	return
}

func (c *Config) handshakeTimeout() time.Duration {
	_, local := c.PaddingDelayBounds()
	return activeHandshakeBudget + local + peerPaddingBudget
}

// HandshakeTimeout also bounds native VLESS admission through UUID validation.
// Nil instances select historical plain-VLESS admission. At most 35 seconds
// are allowed: 5 active + 15 local + 15 remote. Caller/transport limits still win.
func (c *Client) HandshakeTimeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.config.handshakeTimeout()
}

func (s *Server) HandshakeTimeout() time.Duration {
	if s == nil {
		return 0
	}
	return s.config.handshakeTimeout()
}
