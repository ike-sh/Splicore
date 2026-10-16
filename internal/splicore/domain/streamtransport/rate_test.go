package streamtransport

import "testing"

func TestBrutalRatesAndValidation(t *testing.T) {
	for s, want := range map[string]uint64{"": 0, "0": 0, "0 mbps": 0, "524288bps": 65536, "1 Mbps": 125000, "20 m": 2500000, "100mbps": 12500000, "1 TBPS": 125000000000, "524295": 65536} {
		n, e := RateBytes(s)
		if e != nil || n != want {
			t.Fatalf("%q: %d %v", s, n, e)
		}
	}
	for _, s := range []string{"524287", "65535bps", "-1mbps", "+1mbps", "1MB/s", "1.5mbps", "18446744073709551615tbps", "2tbps", "1ps", "1 m bps", "one mbps"} {
		if _, e := RateBytes(s); e == nil {
			t.Fatal("invalid rate accepted", s)
		}
	}
	for _, q := range []QUIC{{Congestion: "bbr", BrutalUp: "1mbps"}, {Congestion: "reno", BrutalDown: "1mbps"}, {Congestion: "force-brutal"}, {Congestion: "brutal", BrutalUp: "-1"}} {
		if q.Validate() == nil {
			t.Fatal("ignored/invalid setting", q)
		}
	}
}
