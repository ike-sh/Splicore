package streamtransport

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHysteriaPortSetBoundaries(t *testing.T) {
	for _, s := range []string{"1", "65535", "1-65535", "1234,5000-6000,7044,8000-9000", "65534-65535,65535,65533-65534", "1,1,2-3,3-4"} {
		p, e := ParseHysteriaPorts(s)
		if e != nil || p.Len() < 1 || p.Len() > 65535 {
			t.Fatal(s, e)
		}
		canonical, e := ParseHysteriaPorts(p.String())
		if e != nil || canonical.String() != p.String() {
			t.Fatal("canonical")
		}
		previous := uint16(0)
		for range 256 {
			port, e := p.Select(previous)
			if e != nil || !p.Contains(port) || p.Len() > 1 && port == previous {
				t.Fatal(s, port, e)
			}
			previous = port
		}
	}
	p, _ := ParseHysteriaPorts("1-65535")
	if p.Len() != 65535 || !p.Contains(65535) {
		t.Fatal("boundary")
	}
	for _, s := range []string{"", "0", "65536", "2-1", "1,", "1,,2", ",1", "-1", "1-", "1--2", "1;2", "1 2", "１", "1-65535,0"} {
		if _, e := ParseHysteriaPorts(s); e == nil {
			t.Fatal("accepted invalid", s)
		}
	}
}
func TestHysteriaObfsUDPValidationAndRedaction(t *testing.T) {
	valid := []string{`{"obfs":{"type":"salamander","password":"SyntheticSecret"}}`, `{"obfs":{"type":"gecko","password":"SyntheticSecret","min_packet_size":512,"max_packet_size":2048}}`, `{"udp":{"ports":"1,65534-65535","hop_interval":5}}`, `{"udp":{"ports":"1-65535","min_hop_interval":5,"max_hop_interval":6}}`, `{"udp":{"server_port_range":"65534-65535"}}`}
	for _, s := range valid {
		var fields map[string]json.RawMessage
		json.Unmarshal([]byte(s), &fields)
		fields["version"] = json.RawMessage(`2`)
		b, _ := json.Marshal(fields)
		var h Hysteria
		if e := json.Unmarshal(b, &h); e != nil {
			t.Fatal(s, e)
		}
		clone := h.Clone()
		if clone.Obfs != nil {
			clone.Obfs.Password = "other"
			if h.Obfs.Password == "other" {
				t.Fatal("alias")
			}
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", h, h.Obfs), "SyntheticSecret") {
			t.Fatal("leak")
		}
	}
	invalid := []string{`"obfs":{"type":"other"}`, `"obfs":{"type":"gecko"}`, `"obfs":{"type":"salamander"}`, `"obfs":{"type":"none","password":"secret"}`, `"obfs":{"type":"gecko","password":"secret","min_packet_size":0}`, `"obfs":{"type":"gecko","password":"secret","min_packet_size":-1}`, `"obfs":{"type":"gecko","password":"secret","max_packet_size":2049}`, `"obfs":{"type":"gecko","password":"secret","min_packet_size":1201}`, `"udp":{"ports":"1","hop_interval":0}`, `"udp":{"ports":"1","hop_interval":4}`, `"udp":{"ports":"1","min_hop_interval":5}`, `"udp":{"ports":"1","min_hop_interval":6,"max_hop_interval":5}`, `"udp":{"ports":"1","hop_interval":5,"min_hop_interval":5,"max_hop_interval":6}`, `"udp":{"server_port_range":"1;2"}`, `"udp":{"ports":"1","server_port_range":"2-3"}`, `"udp":{"hop_interval":5}`, `"obfs":{"type":"none","Password":"secret"}`}
	for _, s := range invalid {
		var h Hysteria
		if json.Unmarshal([]byte(`{"version":2,`+s+`}`), &h) == nil {
			t.Fatal("invalid accepted", s)
		}
	}
	u := HysteriaUDP{Ports: "1,2", MinHopInterval: 5, MaxHopInterval: 6}
	seen := map[time.Duration]bool{}
	for range 64 {
		d, e := u.Interval()
		if e != nil || d < 5*time.Second || d > 6*time.Second {
			t.Fatal(d, e)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Fatal("interval not fresh")
	}
}
func TestHysteriaPacketIdentityIsolation(t *testing.T) {
	base := Hysteria{Version: 2, Obfs: &HysteriaObfs{Type: "salamander", Password: "SyntheticSecret"}, UDP: &HysteriaUDP{Ports: "1,2", HopInterval: 5}}
	seen := map[string]bool{base.PacketIdentity(): true}
	for variant := range 4 {
		h := base.Clone()
		switch variant {
		case 0:
			h.Obfs.Password = "OtherSecret"
		case 1:
			h.Obfs.Type = "gecko"
		case 2:
			h.UDP.Ports = "1,3"
		case 3:
			h.UDP.HopInterval = 6
		}
		key := h.PacketIdentity()
		if seen[key] || strings.Contains(key, "Secret") {
			t.Fatal("unsafe identity")
		}
		seen[key] = true
	}
	h := base.Clone()
	h.UDP.Ports = "2,1,1"
	if h.PacketIdentity() != base.PacketIdentity() {
		t.Fatal("port canonical identity")
	}
}
func FuzzHysteriaPorts(f *testing.F) {
	for _, s := range []string{"1-65535", "65534-65535,1", "0", "1,,2"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, e := ParseHysteriaPorts(s)
		if e != nil {
			return
		}
		if p.Len() < 1 || p.Len() > 65535 {
			t.Fatal("count")
		}
		q, e := ParseHysteriaPorts(p.String())
		if e != nil || q.String() != p.String() {
			t.Fatal("stability")
		}
		port, e := p.Select(0)
		if e != nil || port == 0 || !p.Contains(port) {
			t.Fatal("eligible")
		}
	})
}
