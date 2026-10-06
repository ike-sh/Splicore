package native

import (
	"github.com/ike-sh/Splicore/internal/splicore/engine/traffic"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"net"
)

type meter struct{ traffic.Counter }

func (m *meter) snapshot() ports.Stats { return m.Snapshot() }
func meteredConn(c net.Conn, ms ...*meter) net.Conn {
	counters := make([]*traffic.Counter, 0, len(ms))
	for _, m := range ms {
		if m != nil {
			counters = append(counters, &m.Counter)
		}
	}
	return traffic.Conn(c, counters...)
}
