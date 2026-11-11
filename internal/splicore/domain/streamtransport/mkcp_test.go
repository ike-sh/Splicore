package streamtransport

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestMKCPConfig(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"kind":"mkcp","mkcp":{}}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.MKCPSettings() != DefaultMKCP() || c.Carrier() != "udp" {
		t.Fatal("defaults/carrier")
	}
	if (Config{}).Carrier() != "tcp" {
		t.Fatal("raw carrier")
	}
	clone := c.Clone()
	clone.MKCP.MTU = 576
	if c.MKCP.MTU != 1350 {
		t.Fatal("config aliases clone")
	}
	for _, input := range []string{
		`{"mtu":575}`, `{"mtu":1461}`, `{"tti":9}`, `{"tti":101}`,
		`{"cwndMultiplier":0}`, `{"cwndMultiplier":1025}`, `{"maxSendingWindow":1349}`,
		`{"maxSendingWindow":16777217}`, `{"uplinkCapacity":4294967295}`, `{"downlinkCapacity":4095}`,
		`{"mtu":4294967296}`, `{"mtu":-1}`, `{"tti":1.5}`, `{"MTU":1350}`,
		`{"mtu":null}`, `{"unknown":1}`, `{"mtu":1350,"mtu":1350}`, `null`,
	} {
		t.Run(input, func(t *testing.T) {
			var m MKCP
			if json.Unmarshal([]byte(input), &m) == nil {
				t.Fatal("accepted invalid tuning")
			}
		})
	}
	for _, field := range []string{`"header":{}`, `"seed":"old"`} {
		var m MKCP
		err := json.Unmarshal([]byte("{"+field+"}"), &m)
		if err == nil || !strings.Contains(err.Error(), "legacy") {
			t.Fatal("missing migration error", err)
		}
	}
	for _, input := range []string{`{"kind":"mkcp","path":"/"}`, `{"kind":"tcp","mkcp":{}}`, `{"kind":"mkcp","mkcp":null}`, `{"kind":"mkcp","MKCP":{}}`} {
		if json.Unmarshal([]byte(input), &c) == nil {
			t.Fatal("accepted incompatible member", input)
		}
	}
	for _, mtu := range []uint32{576, 1000, 1350, 1460} {
		for _, tti := range []uint32{10, 37, 50, 100} {
			m := DefaultMKCP()
			m.MTU = mtu
			m.TTI = tti
			if m.Validate() != nil {
				t.Fatal("recommended range")
			}
			expected := uint32(uint64(m.UplinkCapacity) * 1048576 / uint64(mtu) / uint64(1000/tti))
			if expected < 8 {
				expected = 8
			}
			if m.SendSlots() != expected {
				t.Fatal("capacity calculation")
			}
			m.UplinkCapacity = 0
			m.DownlinkCapacity = 0
			if m.SendSlots() != 8 || m.ReceiveSlots() != 8 {
				t.Fatal("zero capacity minimum")
			}
			m.MaxSendingWindow = mtu
			if m.QueueSlots() != 1 || m.Validate() != nil {
				t.Fatal("one packet queue")
			}
		}
	}
	m := DefaultMKCP()
	m.UplinkCapacity = math.MaxUint32
	if m.Validate() == nil {
		t.Fatal("overflow capacity accepted")
	}
	for _, p := range []string{"vless", "vmess", "trojan"} {
		security := "none"
		if p == "trojan" {
			security = "tls"
		}
		if (Config{Kind: "mkcp"}).ValidatePair(p, security) != nil {
			t.Fatal("composition rejected", p)
		}
	}
	if (Config{Kind: "mkcp"}).ValidatePair("vless", "reality") == nil || (Config{Kind: "mkcp"}).ValidatePair("snell", "none") == nil {
		t.Fatal("unqualified pair accepted")
	}
}
