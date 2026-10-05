package native

import (
	"github.com/sagernet/sing-box/internal/splicore/ports"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"net"
	"sync"
	"sync/atomic"
)

type meter struct{ upload, download, sessions, active atomic.Int64 }

func (m *meter) snapshot() ports.Stats {
	return ports.Stats{Upload: m.upload.Load(), Download: m.download.Load(), Sessions: m.sessions.Load(), Active: m.active.Load()}
}
func meterArrays(ms []*meter) ([]*atomic.Int64, []*atomic.Int64) {
	up, down := []*atomic.Int64{}, []*atomic.Int64{}
	for _, m := range ms {
		if m != nil {
			m.sessions.Add(1)
			m.active.Add(1)
			up = append(up, &m.upload)
			down = append(down, &m.download)
		}
	}
	return up, down
}
func meteredConn(c net.Conn, ms ...*meter) net.Conn {
	up, down := meterArrays(ms)
	return &meterConn{ExtendedConn: bufio.NewInt64CounterConn(c, up, down), meters: ms}
}

type meterConn struct {
	N.ExtendedConn
	meters []*meter
	once   sync.Once
}

func (c *meterConn) Close() error {
	c.once.Do(func() {
		for _, m := range c.meters {
			if m != nil {
				m.active.Add(-1)
			}
		}
	})
	return c.ExtendedConn.Close()
}
func (c *meterConn) Upstream() any           { return c.ExtendedConn }
func (c *meterConn) ReaderReplaceable() bool { return true }
func (c *meterConn) WriterReplaceable() bool { return true }
func meteredPacket(c N.PacketConn, ms ...*meter) N.PacketConn {
	up, down := meterArrays(ms)
	return &meterPacket{PacketConn: bufio.NewInt64CounterPacketConn(c, up, nil, down, nil), meters: ms}
}

type meterPacket struct {
	N.PacketConn
	meters []*meter
	once   sync.Once
}

func (c *meterPacket) Close() error {
	c.once.Do(func() {
		for _, m := range c.meters {
			if m != nil {
				m.active.Add(-1)
			}
		}
	})
	return c.PacketConn.Close()
}
func (c *meterPacket) Upstream() any           { return c.PacketConn }
func (c *meterPacket) ReaderReplaceable() bool { return true }
func (c *meterPacket) WriterReplaceable() bool { return true }
