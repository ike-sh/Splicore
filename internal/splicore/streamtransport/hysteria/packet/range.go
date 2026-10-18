package packet

import (
	"errors"
	"net"
	"sync"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

type rangePacket struct {
	net.PacketConn
	cleanup func() error
	once    sync.Once
	err     error
}

func (c *rangePacket) Close() error {
	c.once.Do(func() { c.err = errors.Join(c.PacketConn.Close(), c.cleanup()) })
	return c.err
}

// ServerRange owns only rules created by this listener. Validation precedes
// all commands. Failure leaves socket ownership with the constructor's caller.
func ServerRange(p net.PacketConn, u *cfg.HysteriaUDP) (net.PacketConn, error) {
	if u == nil || u.ServerPortRange == "" {
		return p, nil
	}
	if p == nil || u.Validate() != nil {
		return nil, ErrPacket
	}
	lo, hi, e := cfg.HysteriaServerRange(u.ServerPortRange)
	if e != nil {
		return nil, ErrPacket
	}
	addr, ok := p.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil || addr.IP == nil || addr.Port != int(lo) {
		return nil, errors.New("Hysteria server range must bind its first port on a numeric IP")
	}
	cleanup, e := installRange(addr, lo, hi)
	if e != nil {
		return nil, e
	}
	return &rangePacket{PacketConn: p, cleanup: cleanup}, nil
}
