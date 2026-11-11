package streamtransport

import (
	"encoding/json"
	"testing"
)

func TestPhase33H3ConfigSecurity(t *testing.T) {
	c := Config{Kind: "xhttp"}
	for _, security := range []string{"tls", "none", "reality", ""} {
		err := c.ValidateSecurity(security, []string{"h3"})
		if (err == nil) != (security == "tls") {
			t.Fatal(security, err)
		}
	}
	for _, alpn := range [][]string{{"h3", "h2"}, {"h2", "h3"}, {"splicore-stream/1"}, {"invalid"}} {
		if c.ValidateSecurity("tls", alpn) == nil {
			t.Fatal("ALPN ambiguity", alpn)
		}
	}
	if c.Carrier([]string{"h3"}) != "udp" || c.Carrier([]string{"h2"}) != "tcp" {
		t.Fatal("carrier selection")
	}
}

func FuzzPhase33H3Config(f *testing.F) {
	for _, seed := range []string{`{"kind":"xhttp"}`, `{"kind":"xhttp","xhttp":{"mode":"stream-one"}}`, `{"kind":"xhttp","xhttp":{"scMaxBufferedPosts":-1}}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 16384 {
			return
		}
		var c Config
		if json.Unmarshal(b, &c) != nil {
			return
		}
		_ = c.ValidateClient()
		_ = c.ValidateServer()
		_ = c.ValidateSecurity("tls", []string{"h3"})
		_ = c.ValidateSecurity("reality", []string{"h3"})
		_ = c.Clone()
	})
}
