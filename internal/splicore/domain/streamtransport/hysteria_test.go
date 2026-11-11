package streamtransport

import (
	"encoding/json"
	"testing"
)

func TestHysteriaConfigurationAndComposition(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"hysteria"}`, `{"kind":"hysteria","hysteria":{"version":2,"udp_idle_timeout":2}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"udp_idle_timeout":600,"quic":{"max_idle_timeout":4,"keep_alive_period":1,"max_incoming_streams":8}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"masquerade":{"type":"string","content":"controlled","status":403}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"congestion":"bbr"}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"congestion":"brutal"}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"congestion":"force-brutal","brutal_up":"1 mbps"}}}`,
	} {
		var c Config
		if e := json.Unmarshal([]byte(raw), &c); e != nil || c.ValidatePair("hysteria2", "tls") != nil {
			t.Fatal(raw, e)
		}
		for _, p := range []string{"vless", "vmess", "trojan"} {
			if c.ValidatePair(p, "tls") == nil {
				t.Fatal("arbitrary composition", p)
			}
		}
		if c.ValidatePair("hysteria2", "none") == nil || c.ValidatePair("hysteria2", "reality") == nil || c.ValidateALPN([]string{"h2"}) == nil {
			t.Fatal("TLS/ALPN boundary")
		}
	}
	for _, raw := range []string{
		`{"kind":"hysteria","hysteria":null}`, `{"kind":"hysteria","Hysteria":{"version":2}}`,
		`{"kind":"hysteria","hysteria":{"version":1}}`, `{"kind":"hysteria","hysteria":{"version":0}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"auth":"secret"}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"udp_idle_timeout":1}}`, `{"kind":"hysteria","hysteria":{"version":2,"udp_idle_timeout":601}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"MaxIdleTimeout":5}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"max_idle_timeout":3}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"max_idle_timeout":121}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"max_incoming_streams":-1}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"max_incoming_streams":7}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"congestion":"cubic"}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"congestion":"force-brutal"}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"initial_stream_window":-1}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"quic":{"max_stream_window":18446744073709551616}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"masquerade":{"type":"proxy","url":"file:///tmp/private"}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"masquerade":{"type":"string","status":233}}}`,
		`{"kind":"hysteria","hysteria":{"version":2,"masquerade":{"type":"string","headers":{"Hysteria-UDP":"true"}}}}`,
		`{"kind":"hysteria","path":"/ignored"}`, `{"kind":"tcp","hysteria":{"version":2}}`,
	} {
		var c Config
		if e := json.Unmarshal([]byte(raw), &c); e == nil {
			t.Fatal("malformed accepted", raw)
		}
	}
}
