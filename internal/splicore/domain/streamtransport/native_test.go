package streamtransport

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestPhase31NativeConfig(t *testing.T) {
	for _, kind := range []string{"http", "h2", "quic-stream"} {
		c := Config{Kind: kind}
		if e := c.Validate(); e != nil {
			t.Fatal(e)
		}
		for _, p := range []string{"vless", "vmess", "trojan"} {
			if e := c.ValidatePair(p, "tls"); e != nil {
				t.Fatal(p, kind, e)
			}
		}
		for _, p := range []string{"shadowquic", "hysteria2", "naive", "shadowsocks", "snell"} {
			if c.ValidatePair(p, "tls") == nil {
				t.Fatal("unsupported binding accepted", p)
			}
		}
		for _, security := range []string{"none", "reality", ""} {
			if c.ValidatePair("vless", security) == nil {
				t.Fatal("unsafe security accepted")
			}
		}
		want := "http/1.1"
		if kind == "h2" {
			want = "h2"
		}
		if kind == "quic-stream" {
			want = GenericQUICALPN
		}
		if c.ValidateALPN([]string{want}) != nil || c.ValidateALPN([]string{"h3"}) == nil {
			t.Fatal("ALPN confusion")
		}
		if c.PutQuery(url.Values{}) == nil {
			t.Fatal("lossy share accepted")
		}
		if _, e := Query(url.Values{"type": {kind}}); e == nil {
			t.Fatal("foreign share accepted")
		}
	}
	for _, raw := range []string{`{"kind":"http","path":"/a%2Fb"}`, `{"kind":"h2","path":"/a/../b"}`, `{"kind":"http","path":"//a"}`, `{"kind":"h2","path":"/a?x=1"}`, `{"kind":"http","headers":{"Content-Type":"text/plain"}}`, `{"kind":"h2","headers":{"Forwarded":"evil"}}`, `{"kind":"quic-stream","path":"/"}`, `{"kind":"quic-stream","alpn":"h3"}`, `{"kind":"h2","idle_timeout":-1}`, `{"kind":"http","xhttp":{}}`, `{"kind":"HTTP"}`, `{"kind":"h2","headers":{"X-A":"a\r\nb"}}`, `{"kind":"http","kind":"tcp"}`, `{"kind":"h2","service_name":"evil"}`, `{"kind":"quic-stream","headers":{"X-A":"x"}}`} {
		var c Config
		e := json.Unmarshal([]byte(raw), &c)
		if e == nil {
			e = c.Validate()
		}
		if e == nil {
			t.Fatal("invalid config accepted", raw)
		}
	}
}

func FuzzPhase31NativeConfig(f *testing.F) {
	f.Add([]byte(`{"kind":"h2","path":"/native"}`))
	f.Add([]byte(`{"kind":"quic-stream"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 32768 {
			return
		}
		var c Config
		if json.Unmarshal(b, &c) != nil {
			return
		}
		_ = c.Validate()
		_ = c.ValidatePair("vless", "tls")
		_ = c.ValidateServer()
		_ = c.ValidateALPN([]string{"h2"})
		_ = c.Clone()
	})
}
