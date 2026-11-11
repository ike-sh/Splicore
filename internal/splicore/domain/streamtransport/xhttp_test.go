package streamtransport

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestXHTTPRange(t *testing.T) {
	for _, s := range []string{`0`, `-1`, `2147483647`, `"1-20"`, `"-1-5"`, `"-4--1"`, `""`, `"7"`} {
		t.Run(s, func(t *testing.T) {
			var r Range
			if json.Unmarshal([]byte(s), &r) != nil {
				t.Fatal(s)
			}
			b, _ := json.Marshal(r)
			var q Range
			if json.Unmarshal(b, &q) != nil || q != r {
				t.Fatal("range roundtrip")
			}
		})
	}
	for _, s := range []string{`null`, `true`, `{}`, `[]`, `"9-1"`, `"-1--4"`, `2147483648`, `-2147483649`, `"1-4294967296"`, `1.5`, `"1--2"`, `"1-2-3"`} {
		t.Run("reject-"+s, func(t *testing.T) {
			var r Range
			if json.Unmarshal([]byte(s), &r) == nil {
				t.Fatal("accepted invalid range")
			}
		})
	}
	var r Range
	_ = json.Unmarshal([]byte(`"3-6"`), &r)
	n, e := r.Pick(bytes.NewReader(make([]byte, 32)))
	if e != nil || n != 3 {
		t.Fatal("deterministic range", n, e)
	}
}
func TestXHTTPConfigRejections(t *testing.T) {
	for _, s := range []string{
		`{"mode":"unknown"}`, `{"xPaddingBytes":-1}`, `{"xPaddingBytes":"0-2"}`, `{"xPaddingMethod":"unknown"}`, `{"xPaddingPlacement":"path"}`,
		`{"uplinkHTTPMethod":"GET"}`, `{"uplinkHTTPMethod":"bad method"}`, `{"uplinkHTTPMethod":"CONNECT"}`, `{"sessionIDPlacement":"body"}`, `{"seqPlacement":"body"}`, `{"uplinkDataPlacement":"query"}`, `{"uplinkDataPlacement":"header","mode":"auto"}`,
		`{"scMaxEachPostBytes":-1}`, `{"scMaxBufferedPosts":-1}`, `{"serverMaxHeaderBytes":-1}`, `{"xmux":{"maxConnections":1,"maxConcurrency":1}}`,
		`{"sessionIDTable":"number","sessionIDLength":1}`, `{"sessionIDTable":"number","sessionIDLength":0}`, `{"sessionIDLength":5}`, `{"sessionIDTable":"abc/","sessionIDLength":20}`, `{"sessionIDTable":"aa","sessionIDLength":64}`,
		`{"downloadSettings":{"endpoint":{"host":"127.0.0.1","port":443},"transport":{"kind":"tcp"},"security":"none","tls":{"enabled":false}}}`,
		`{"Mode":"auto"}`, `{"mode":null}`, `{"extra":{}}`, `{"mode":"auto","mode":"packet-up"}`, `{"seqPlacement":null}`,
	} {
		t.Run(s, func(t *testing.T) {
			var x XHTTP
			e := json.Unmarshal([]byte(s), &x)
			if e == nil {
				e = x.Validate()
			}
			if e == nil {
				t.Fatal("accepted invalid XHTTP")
			}
		})
	}
	for _, p := range []string{"/../escape", "/%2e%2e/escape", "/a\\b", "/a#fragment", "/a\r\n", "/a?x=%zz", "/a?x=1;2", "/a\x00", "/a b"} {
		t.Run(p, func(t *testing.T) {
			if (Config{Kind: "xhttp", Path: p}).Validate() == nil {
				t.Fatal("path accepted")
			}
		})
	}
	if (Config{Kind: "tcp", XHTTP: &XHTTP{}}).Validate() == nil {
		t.Fatal("foreign transport options")
	}
	if (Config{Kind: "xhttp"}).ValidateALPN([]string{"h3", "h2"}) == nil {
		t.Fatal("H3 fallback")
	}
	if (Config{Kind: "xhttp", XHTTP: &XHTTP{Download: &Download{}}}).ValidateServer() == nil {
		t.Fatal("server download leg")
	}
	for _, x := range []XHTTP{{NoSSE: true}, {HeaderBytes: 8192}, {KeepAlive: Range{1, 1}}, {Buffered: 30}, {Mode: "packet-up", NoGRPC: true}, {Mode: "stream-up", PacketBytes: Range{1024, 1024}}} {
		if (Config{Kind: "xhttp", XHTTP: &x}).ValidateClient() == nil {
			t.Fatal("inapplicable client control accepted")
		}
	}
	for _, x := range []XHTTP{{PaddingKey: "custom"}, {PaddingPlacement: "cookie"}, {SessionPlacement: "header", SessionKey: "Content-Length"}, {SequencePlacement: "header", SequenceKey: "Host"}, {PaddingObfs: true, PaddingPlacement: "header", PaddingHeader: "Content-Type"}} {
		if (Config{Kind: "xhttp", XHTTP: &x}).Validate() == nil {
			t.Fatal("inapplicable or conflicting metadata accepted")
		}
	}
}
func TestXHTTPDefaultsAndModes(t *testing.T) {
	x := (XHTTP{}).Normalized()
	if x.Mode != "auto" || x.PacketBytes.Max != 1000000 || x.Padding != (Range{100, 1000}) || x.HeaderBytes != 8192 || x.Buffered != 30 || x.XMUX.MaxConnections.Max != 3 {
		t.Fatal("defaults")
	}
	for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
		for _, reality := range []bool{false, true} {
			t.Run(mode+map[bool]string{true: "reality", false: "TLS"}[reality], func(t *testing.T) {
				x := XHTTP{Mode: mode}
				selected := x.SelectMode(reality)
				want := mode
				if mode == "auto" {
					want = "packet-up"
					if reality {
						want = "stream-one"
					}
				}
				if selected != want {
					t.Fatal(selected, want)
				}
			})
		}
	}
	if (XHTTP{Download: &Download{}}).SelectMode(true) != "stream-up" {
		t.Fatal("REALITY split auto")
	}
	for _, p := range []string{"path", "header", "query", "cookie"} {
		t.Run(p, func(t *testing.T) {
			c := Config{Kind: "xhttp", Path: "example?fixed=1", XHTTP: &XHTTP{SessionPlacement: p, SequencePlacement: p, Mode: "packet-up"}}
			if c.Validate() != nil {
				t.Fatal("placement")
			}
			path, q := c.XHTTPPath()
			want := "/example"
			if p == "path" {
				want += "/"
			}
			if path != want || q != "fixed=1" {
				t.Fatal(path, q)
			}
		})
	}
	for _, table := range []string{"ALPHABET", "Alphabet", "BASE36", "Base62", "HEX", "alphabet", "base36", "hex", "number"} {
		t.Run(table, func(t *testing.T) {
			x := XHTTP{SessionTable: table, SessionLength: Range{40, 40}}
			if x.Validate() != nil {
				t.Fatal("table")
			}
		})
	}
	for _, alpn := range [][]string{nil, {"h2"}, {"http/1.1"}, {"h2", "http/1.1"}} {
		if (Config{Kind: "xhttp"}).ValidateALPN(alpn) != nil {
			t.Fatal(alpn)
		}
	}
}
