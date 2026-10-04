package client

import (
	"encoding/json"
	"testing"
)

func TestTUNAddressAndCaptureBoundaries(t *testing.T) {
	base := TUNSettings{Interface: "splicore0", Addresses: []string{"198.18.0.1/30", "fd13:1234::1/126"}, MTU: 1500, AutoRoute: true, Stack: "gvisor"}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"198.18.0.0/30", "198.18.0.2/30", "198.18.0.3/30", "fd13:1234::3/126", "::ffff:198.18.0.1/120", "127.0.0.1/30", "198.18.0.1/32"} {
		c := base
		c.Addresses = []string{address}
		if c.Validate() == nil {
			t.Fatal("unusable TUN range", address)
		}
	}
	for _, prefix := range []string{"198.19.0.1/24", "garbage", "::ffff:198.19.0.0/120"} {
		c := base
		c.Include = []string{prefix}
		if c.Validate() == nil {
			t.Fatal("invalid capture range", prefix)
		}
	}
	c := base
	c.AutoRoute = false
	c.Include = []string{"0.0.0.0/0"}
	if c.Validate() == nil {
		t.Fatal("implicit host capture")
	}
}

func FuzzTUNSettings(f *testing.F) {
	f.Add([]byte(`{"interface":"splicore0","addresses":["198.18.0.1/30"],"mtu":1500,"auto_route":true,"include":["0.0.0.0/0"]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var settings TUNSettings
		if json.Unmarshal(b, &settings) == nil && settings.Validate() == nil {
			encoded, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			var roundtrip TUNSettings
			if json.Unmarshal(encoded, &roundtrip) != nil || roundtrip.Validate() != nil {
				t.Fatal("TUN validation round trip")
			}
		}
	})
}
