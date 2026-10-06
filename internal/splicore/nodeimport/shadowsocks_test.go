package nodeimport

import (
	ss "github.com/ike-sh/Splicore/internal/splicore/protocol/shadowsocks"
	"testing"
)

func TestShadowsocksExternalUDPFlag(t *testing.T) {
	for _, c := range []struct {
		format, body string
		udp          bool
	}{
		{"mihomo", `{"proxies":[{"name":"synthetic","type":"ss","server":"localhost","port":1234,"cipher":"aes-128-gcm","password":"synthetic-only","udp":false}]}`, false},
		{"sing-box", `{"type":"shadowsocks","tag":"synthetic","server":"localhost","server_port":1234,"method":"aes-128-gcm","password":"synthetic-only","network":"tcp"}`, false},
		{"mihomo", `{"proxies":[{"name":"synthetic","type":"ss","server":"localhost","port":1234,"cipher":"aes-128-gcm","password":"synthetic-only","udp":true}]}`, true},
	} {
		r, e := Parse(c.format, []byte(c.body))
		if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
			t.Fatal(c.format, e, r.Issues)
		}
		o, e := ss.DecodeClient(r.Candidates[0].Node.Options.Data)
		if e != nil || o.UDP != c.udp {
			t.Fatal("UDP capability lost", e)
		}
	}
}
