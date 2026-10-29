package streamtransport

import (
	"encoding/json"
	"testing"
)

func TestXHTTPH3BoundedIntent(t *testing.T) {
	valid := `{"kind":"xhttp","h3":{"disableChromeParrot":true,"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":1048576,"initConnectionReceiveWindow":524288,"maxConnectionReceiveWindow":8388608,"maxIncomingStreams":64,"maxIdleTimeout":30,"keepAlivePeriod":10}}`
	var c Config
	if err := json.Unmarshal([]byte(valid), &c); err != nil {
		t.Fatal(err)
	}
	cloned := c.Clone()
	cloned.H3.MaxIncomingStreams = 8
	if c.H3.MaxIncomingStreams != 64 {
		t.Fatal("mutable H3 alias")
	}
	if c.ValidateSecurity("tls", []string{"h3"}) != nil || c.ValidateSecurity("tls", []string{"h2"}) == nil || c.ValidateSecurity("reality", []string{"h3"}) == nil {
		t.Fatal("H3 security boundary")
	}
	for _, raw := range []string{`null`, `{"disableChromeParrot":null}`, `{"DisableChromeParrot":true}`, `{"maxIncomingStreams":1}`, `{"maxIncomingStreams":1025}`, `{"maxIdleTimeout":121}`, `{"keepAlivePeriod":1}`, `{"initStreamReceiveWindow":1}`, `{"maxStreamReceiveWindow":67108865}`, `{"initStreamReceiveWindow":65536,"maxStreamReceiveWindow":16384}`, `{"maxIdleTimeout":30,"maxIdleTimeout":60}`, `{"zeroRTT":true}`} {
		var h H3
		if json.Unmarshal([]byte(raw), &h) == nil {
			t.Fatal("unbounded or ambiguous H3 intent", raw)
		}
	}
}

func FuzzXHTTPH3Options(f *testing.F) {
	f.Add([]byte(`{"disableChromeParrot":true,"maxIncomingStreams":8}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		var h H3
		if json.Unmarshal(b, &h) == nil && h.Validate() != nil {
			t.Fatal("invalid accepted")
		}
	})
}
