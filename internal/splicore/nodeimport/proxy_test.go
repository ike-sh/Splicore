package nodeimport

import (
	"github.com/ike-sh/Splicore/internal/splicore/protocol/proxy"
	"strings"
	"testing"
)

func TestPhase20ProxyURIAndExternal(t *testing.T) {
	for _, s := range []string{"socks://127.0.0.1:1080", "socks5://synthetic:fixture@127.0.0.1:1080", "socks5h://synthetic:fixture@[::1]:1080", "http://synthetic:fixture@127.0.0.1:8080"} {
		c, e := ParseURI(s)
		if e != nil {
			t.Fatal(e)
		}
		o, e := proxy.Decode(c.Node.Options.Data)
		if e != nil || o.UDP != (c.Node.Protocol.Protocol == "socks5") {
			t.Fatal("capability")
		}
	}
	for _, s := range []string{"http://u:p@a", "http://u:p@a:80/path", "socks5://u@a:80", "http://u:p@a:80?x=1", "https://u:p@a:80"} {
		if _, e := ParseURI(s); e == nil {
			t.Fatal("unsupported URI accepted")
		}
	}
	for _, format := range []string{"sing-box", "mihomo"} {
		raw := `{"outbounds":[{"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":1080,"version":"5","username":"synthetic","password":"fixture"}]}`
		if format == "mihomo" {
			raw = `{"proxies":[{"type":"socks5","name":"proxy","server":"127.0.0.1","port":1080,"udp":true,"username":"synthetic","password":"fixture"}]}`
		}
		r, e := Parse(format, []byte(raw))
		if e != nil || len(r.Issues) != 0 || len(r.Candidates) != 1 {
			t.Fatal("external import", e, r.Issues)
		}
	}
}
func FuzzProxyURI(f *testing.F) {
	f.Add("socks5h://u:p@127.0.0.1:1080")
	f.Fuzz(func(t *testing.T, s string) {
		if !strings.HasPrefix(s, "socks://") && !strings.HasPrefix(s, "socks5://") && !strings.HasPrefix(s, "socks5h://") {
			s = "socks5h://" + s
		}
		_, _ = ParseURI(s)
	})
}
