package endpoint

import (
	"crypto/ecdh"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func awgConfig() AmneziaWG {
	a, b := [32]byte{1}, [32]byte{0, 2}
	private, _ := ParseSecret(EncodeKey(a))
	peer, _ := ecdh.X25519().NewPrivateKey(b[:])
	var pub [32]byte
	copy(pub[:], peer.PublicKey().Bytes())
	return AmneziaWG{Protocol: "amneziawg", Version: "3.1", Tag: "awg", PrivateKey: private, Addresses: []string{"10.37.0.1/32"}, Peers: []WireGuardPeer{{PublicKey: EncodeKey(pub), AllowedIPs: []string{"10.37.0.2/32"}}}}
}

func TestAWGRanges(t *testing.T) {
	for _, s := range []string{"0", "0-0", "1-2", "65535", "4294967295", "0-4294967295"} {
		r, e := ParseAWGRange(s, 32)
		if e != nil || !r.Valid(32) {
			t.Fatalf("valid range %q", s)
		}
	}
	for _, s := range []string{"-1", "10-", "-20", "20-10", "1-2-3", "9999999999999999999999999", "+1", " 1", "1.0", "1e3", "4294967296"} {
		if _, e := ParseAWGRange(s, 32); e == nil {
			t.Errorf("accepted malformed range %q", s)
		}
	}
	for _, s := range []string{"65536", "0-65536", "4294967295"} {
		if _, e := ParseAWGRange(s, 16); e == nil {
			t.Error("uint16 overflow")
		}
	}
}

func TestAWGConfigValidation(t *testing.T) {
	if e := awgConfig().Validate(); e != nil {
		t.Fatal(e)
	}
	tests := map[string]func(*AmneziaWG){
		"protocol": func(c *AmneziaWG) { c.Protocol = "wireguard" }, "version": func(c *AmneziaWG) { c.Version = "2.0" }, "backend": func(c *AmneziaWG) { c.Backend = "other" },
		"fixed-overlap": func(c *AmneziaWG) { c.H1 = &AWGRange{2, 2} }, "range-overlap": func(c *AmneziaWG) { c.H1 = &AWGRange{100, 200}; c.H2 = &AWGRange{150, 160} }, "edge-overlap": func(c *AmneziaWG) { c.H1 = &AWGRange{0, 4294967295} },
		"reversed": func(c *AmneziaWG) { c.H1 = &AWGRange{6, 5} }, "junk-reversed": func(c *AmneziaWG) { c.Jmin = 30; c.Jmax = 10 }, "junk-work": func(c *AmneziaWG) { c.Jc = 65535 },
		"padding-overflow": func(c *AmneziaWG) { c.ContentPaddingAddition = AWGRange{0, 65536} }, "timing-zero": func(c *AmneziaWG) { c.RekeyTimeout = AWGRange{0, 1} }, "rekey-reject": func(c *AmneziaWG) { c.RekeyAfterTime = AWGRange{180, 180} },
		"rt": func(c *AmneziaWG) { c.RandomTrailers = true }, "CPS": func(c *AmneziaWG) { c.I1 = "<r -1>" }, "injection": func(c *AmneziaWG) { c.I1 = "<b 01>\nprivate_key=secret" }, "sizing": func(c *AmneziaWG) { c.S4 = 65535 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := awgConfig()
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	var bytes [32]byte
	bytes[0] = 17
	key, _ := ParseSecret(EncodeKey(bytes))
	for i := range 4 {
		c := awgConfig()
		c.HeaderProtectionKey = key
		c.S1, c.S2, c.S3, c.S4 = 12, 12, 12, 12
		switch i {
		case 0:
			c.S1 = 11
		case 1:
			c.S2 = 11
		case 2:
			c.S3 = 11
		case 3:
			c.S4 = 11
		}
		if e := c.Validate(); e == nil || !strings.Contains(e.Error(), fmt.Sprintf("S%d", i+1)) {
			t.Fatal("incorrect nonce field error")
		}
	}
	c := awgConfig()
	c.HeaderProtectionKey = key
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), EncodeKey(bytes)) || strings.Contains(fmt.Sprintf("%+v", c), EncodeKey(bytes)) {
		t.Fatal("HPK leaked")
	}
	c.H1 = &AWGRange{100, 101}
	clone := c.Clone()
	clone.H1.Min = 999
	if c.H1.Min != 100 {
		t.Fatal("mutable header range shared")
	}
}

func TestCPSGrammarAndBounds(t *testing.T) {
	for _, s := range []string{"", "<b 0x01ff><t><r 0><rc 1000><rd 0>", "<d><ds><dz 2>", "<r 1000>", "<rd 1000>"} {
		if _, e := ParseCPS(s); e != nil {
			t.Fatalf("valid CPS rejected: %s", s)
		}
	}
	for _, s := range []string{"text<b 01>", "<b >", "<b 0>", "<b zz>", "<r -1>", "<rc 1001>", "<rd 999999999999999999>", "<r 1 2>", "<t 3>", "<<t>>", "<t", "<unknown>", strings.Repeat("<r 1000>", 2), strings.Repeat("<r 0>", 129)} {
		if _, e := ParseCPS(s); e == nil {
			t.Fatal("malformed CPS accepted")
		}
	}
}

func FuzzAWGRange(f *testing.F) {
	for _, s := range []string{"0", "1-2", "4294967295", "-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, e := ParseAWGRange(s, 32)
		if e == nil && !r.Valid(32) {
			t.Fatal("invalid numeric bounds")
		}
	})
}

func FuzzCPS(f *testing.F) {
	for _, s := range []string{"<t>", "<b ff><rc 1000>", "<r -1>", "<r 999999999999999>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, e := ParseCPS(s)
		if e == nil && (c.Size > MaxCPSPacket || len(c.Tags) > 128) {
			t.Fatal("unbounded CPS")
		}
	})
}

func FuzzAWGConfig(f *testing.F) {
	f.Add([]byte(`{"protocol":"amneziawg","version":"3.1","h1":"1-2"}`))
	f.Fuzz(func(_ *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var c AmneziaWG
		if json.Unmarshal(b, &c) == nil {
			_ = c.Validate()
		}
	})
}
