package hysteria

import (
	"context"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"sync/atomic"
	"testing"
)

func TestCongestionAsymmetricSelectionAndActualControllers(t *testing.T) {
	st, ct := material(t)
	for _, row := range []struct {
		name           string
		client, server cfg.QUIC
		cm, sm         string
		cr, sr         uint64
	}{
		{"bbr", cfg.QUIC{Congestion: "bbr"}, cfg.QUIC{Congestion: "bbr"}, "bbr", "bbr", 0, 0},
		{"asymmetric", cfg.QUIC{Congestion: "brutal", BrutalUp: "20mbps", BrutalDown: "100mbps"}, cfg.QUIC{Congestion: "brutal", BrutalUp: "40mbps", BrutalDown: "1mbps"}, "brutal", "brutal", 125000, 5000000},
		{"inverse", cfg.QUIC{Congestion: "brutal", BrutalUp: "1mbps", BrutalDown: "20mbps"}, cfg.QUIC{Congestion: "brutal", BrutalUp: "100mbps", BrutalDown: "40mbps"}, "brutal", "brutal", 125000, 2500000},
		{"auto-fallback", cfg.QUIC{Congestion: "brutal", BrutalUp: "1mbps"}, cfg.QUIC{Congestion: "bbr"}, "bbr", "bbr", 0, 0},
		{"unlimited", cfg.QUIC{Congestion: "brutal", BrutalUp: "20mbps", BrutalDown: "1mbps"}, cfg.QUIC{Congestion: "brutal"}, "brutal", "brutal", 2500000, 125000},
		{"force", cfg.QUIC{Congestion: "force-brutal", BrutalUp: "20mbps"}, cfg.QUIC{Congestion: "bbr"}, "brutal", "bbr", 2500000, 0},
		{"server-force", cfg.QUIC{Congestion: "bbr"}, cfg.QUIC{Congestion: "force-brutal", BrutalUp: "100mbps", BrutalDown: "1mbps"}, "bbr", "brutal", 0, 12500000},
	} {
		t.Run(row.name, func(t *testing.T) {
			admitted := make(chan *Connection, 1)
			s, a := serve(t, st, cfg.Hysteria{Version: 2, QUIC: row.server}, func(string) (string, bool) { return "A", true }, func(c *Connection) Hooks { return Hooks{Admitted: func() { admitted <- c }} })
			var created, open atomic.Int64
			m, e := NewManager(context.Background(), ClientConfig{TLS: ct, Password: "A", Settings: cfg.Hysteria{Version: 2, QUIC: row.client}, Socket: socket(t, a, &created, &open)})
			if e != nil {
				t.Fatal(e)
			}
			c, e := m.Acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			peer := <-admitted
			for _, p := range []struct {
				c    *Connection
				mode string
				rate uint64
			}{{c, row.cm, row.cr}, {peer, row.sm, row.sr}} {
				s := p.c.Congestion()
				if s.Selected != p.mode || s.EffectiveRateBytesPerSecond != p.rate || s.Controller != "native "+p.mode || p.c.controller == nil {
					t.Fatal(s)
				}
				t.Logf("controller %+v", s)
			}
			next, e := m.Acquire(context.Background())
			if e != nil || next != c || created.Load() != 1 {
				t.Fatal("reuse", e)
			}
			m.Close()
			s.Close(context.Background())
			if open.Load() != 0 {
				t.Fatal("controller owner socket leaked")
			}
		})
	}
}
