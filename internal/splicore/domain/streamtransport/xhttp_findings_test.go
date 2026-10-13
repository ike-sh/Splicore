package streamtransport

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func headerCases(s string) []string {
	return []string{s, strings.ToLower(s), strings.ToUpper(s), strings.ToLower(s[:1]) + strings.ToUpper(s[1:])}
}
func TestXHTTPMetadataOwnership(t *testing.T) {
	x := XHTTP{Mode: "packet-up", SessionPlacement: "header", SequencePlacement: "header", DataPlacement: "header", PaddingObfs: true, PaddingPlacement: "header"}
	for _, key := range []string{"X-Session", "X-Seq", "X-Data-0", "X-Data-4095", "X-Padding", "Content-Type", "Referer", "Cookie", "Cache-Control", "X-Accel-Buffering", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Host"} {
		for _, variant := range headerCases(key) {
			t.Run(variant, func(t *testing.T) {
				c := Config{Kind: "xhttp", XHTTP: &x, Headers: map[string]string{variant: "override"}}
				if c.Validate() == nil {
					t.Fatal("transport metadata override accepted")
				}
			})
		}
	}
	if (Config{Kind: "xhttp", XHTTP: &x, Host: "example.test:443", Headers: map[string]string{"X-Application": "ok"}}).Validate() != nil {
		t.Fatal("ordinary header / authority rejected")
	}
	for _, key := range headerCases("X-Session") {
		t.Run("session-sequence-"+key, func(t *testing.T) {
			v := x
			v.SessionKey = "X-Session"
			v.SequenceKey = key
			if v.Validate() == nil {
				t.Fatal("case equivalent association keys accepted")
			}
		})
	}
	for _, key := range headerCases("X-Data-0") {
		for _, role := range []string{"session", "sequence", "padding"} {
			t.Run(role+key, func(t *testing.T) {
				v := x
				switch role {
				case "session":
					v.SessionKey = key
				case "sequence":
					v.SequenceKey = key
				case "padding":
					v.PaddingHeader = key
				}
				if v.Validate() == nil {
					t.Fatal("data namespace collision accepted")
				}
			})
		}
	}
	for _, key := range headerCases("X-Padding") {
		v := x
		v.SessionKey = key
		if v.Validate() == nil {
			t.Fatal("padding/session collision")
		}
	}
	for _, role := range []string{"session", "sequence", "padding"} {
		v := XHTTP{Mode: "packet-up", DataPlacement: "cookie", DataKey: "x_data", PaddingObfs: true, PaddingPlacement: "cookie"}
		switch role {
		case "session":
			v.SessionPlacement = "cookie"
			v.SessionKey = "x_data_0"
		case "sequence":
			v.SequencePlacement = "cookie"
			v.SequenceKey = "x_data_0"
		case "padding":
			v.PaddingKey = "x_data_0"
		}
		if v.Validate() == nil {
			t.Fatal("data cookie namespace collision", role)
		}
	}
}

func TestXHTTPMinimumGeneratedSessionEntropy(t *testing.T) {
	for _, tc := range []struct {
		table  string
		lo, hi int32
		ok     bool
	}{
		{"number", 1, 10, false}, {"number", 36, 256, false}, {"number", 37, 37, true}, {"number", 37, 256, true},
		{"hex", 30, 256, false}, {"hex", 31, 256, true}, {"Base62", 20, 256, false}, {"Base62", 21, 256, true},
		{"ab", 121, 256, false}, {"ab", 122, 256, true},
	} {
		t.Run(fmt.Sprintf("%s/%d-%d", tc.table, tc.lo, tc.hi), func(t *testing.T) {
			x := XHTTP{SessionTable: tc.table, SessionLength: Range{tc.lo, tc.hi}}
			if (x.Validate() == nil) != tc.ok {
				t.Fatal("shortest ID entropy policy", tc)
			}
		})
	}
}

func TestXHTTPFirstPayloadBudget(t *testing.T) {
	for _, tc := range []struct {
		r  Range
		ok bool
	}{
		{Range{}, true}, {Range{-1, -1}, true}, {Range{0, 100}, true}, {Range{30, 300}, true}, {Range{6000, 6000}, true},
		{Range{XHTTPMaxFirstPacketIntervalMs, XHTTPMaxFirstPacketIntervalMs}, true},
		{Range{XHTTPMaxFirstPacketIntervalMs + 1, XHTTPMaxFirstPacketIntervalMs + 1}, false}, {Range{60000, 60000}, false},
	} {
		x := XHTTP{Mode: "packet-up", Interval: tc.r}
		if (x.Validate() == nil) != tc.ok {
			t.Fatal("admission/coalescing budget", tc)
		}
	}
	if XHTTPAdmissionTimeout != 2*XHTTPLegAdmissionTimeout+time.Duration(XHTTPMaxFirstPacketIntervalMs)*time.Millisecond {
		t.Fatal("budget arithmetic")
	}
}
