package ports

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStatsOptionalTransportCounterCompatibility(t *testing.T) {
	legacy := `{"upload_bytes":"9007199254740993","download_bytes":"8","sessions_total":"7","sessions_active":"1"}`
	s := Stats{TCPSessions: 99, TCPActive: 99, UDPSessions: 99, UDPActive: 99}
	if err := json.Unmarshal([]byte(legacy), &s); err != nil || s.Upload != 9007199254740993 || s.TCPSessions != 0 || s.TCPActive != 0 || s.UDPSessions != 0 || s.UDPActive != 0 {
		t.Fatal("legacy stats precision/optional fields", err)
	}
	b, err := json.Marshal(s)
	if err != nil || strings.Contains(string(b), "tcp_sessions") || strings.Contains(string(b), "udp_sessions") {
		t.Fatal("zero optional counters changed legacy response", err)
	}
	s.TCPSessions, s.TCPActive, s.UDPSessions, s.UDPActive = 5, 1, 2, 0
	b, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var got Stats
	if err = json.Unmarshal(b, &got); err != nil || got != s {
		t.Fatal("transport counter roundtrip", err)
	}
	for _, counter := range []string{"-1", "9223372036854775808", "invalid"} {
		bad := strings.TrimSuffix(legacy, "}") + `,"udp_sessions_active":"` + counter + `"}`
		if json.Unmarshal([]byte(bad), &got) == nil {
			t.Fatal("invalid optional counter accepted")
		}
	}
}
