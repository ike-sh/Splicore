package hysteria2

import (
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"strings"
	"testing"
)

func TestURIMultiPortObfsRoundTrip(t *testing.T) {
	for _, scheme := range []string{"hy2", "hysteria2"} {
		for _, host := range []string{"example.test", "127.0.0.1", "[::1]"} {
			for _, kind := range []string{"salamander", "gecko"} {
				raw := scheme + "://Synthetic%3APassword%40%25@" + host + ":1,65534-65535/?obfs=" + kind + "&obfs-password=Synthetic%26%2B%25Secret&sni=server.test#Display%20Name"
				v, e := ParseURI(raw)
				if e != nil {
					t.Fatal(e)
				}
				if v.Endpoint.Port != 1 || v.Transport.Hysteria.UDP.Ports != "1,65534-65535" || v.Password.Reveal() != "Synthetic:Password@%" || v.Transport.Hysteria.Obfs.Password != "Synthetic&+%Secret" {
					t.Fatal("lost fields")
				}
				encoded, e := EncodeURI(v)
				if e != nil {
					t.Fatal(e)
				}
				again, e := ParseURI(encoded)
				if e != nil || again.Transport.HysteriaSettings().PacketIdentity() != v.Transport.HysteriaSettings().PacketIdentity() || again.Password.Reveal() != v.Password.Reveal() || again.Name != v.Name {
					t.Fatal("round trip", e)
				}
			}
		}
	}
}
func TestURIRejectsLossyTuningAndMalformed(t *testing.T) {
	base := "hy2://SyntheticPassword@localhost:443/?"
	for _, query := range []string{"obfs=other", "obfs=salamander", "obfs-password=x", "obfs=none", "obfs=gecko&obfs-password=x&obfs=gecko", "minPacketSize=512", "hopInterval=5s", "insecure=1", "sni=%zz"} {
		if _, e := ParseURI(base + query); e == nil {
			t.Fatal(query)
		}
	}
	for _, authority := range []string{"localhost:0", "localhost:65536", "localhost:2-1", "localhost:1,", "::1:443", "[::1]:1,,2", "localhost:1;2", "localhost:"} {
		if _, e := ParseURI("hy2://SyntheticPassword@" + authority); e == nil {
			t.Fatal("invalid authority", authority)
		}
	}
	v, e := ParseURI(base + "obfs=gecko&obfs-password=SyntheticSecret")
	if e != nil {
		t.Fatal(e)
	}
	v.Transport.Hysteria.Obfs.MinPacketSize = 512
	if _, e := EncodeURI(v); e == nil {
		t.Fatal("silently lost Gecko sizes")
	}
	v.Transport.Hysteria.Obfs.MinPacketSize = 0
	v.Transport.Hysteria.UDP = &cfg.HysteriaUDP{Ports: "1,2", HopInterval: 5}
	if _, e := EncodeURI(v); e == nil {
		t.Fatal("silently lost hop interval")
	}
}
func FuzzHysteriaURI(f *testing.F) {
	f.Add("hy2://SyntheticPassword@[::1]:65534-65535/?obfs=gecko&obfs-password=SyntheticSecret")
	f.Add("hy2://x@host:0")
	f.Fuzz(func(t *testing.T, s string) {
		v, e := ParseURI(s)
		if e != nil {
			return
		}
		if v.Endpoint.Port == 0 || v.Transport.Validate() != nil {
			t.Fatal("invalid parsed value")
		}
		out, e := EncodeURI(v)
		if e == nil {
			again, e := ParseURI(out)
			if e != nil || again.Password.Reveal() != v.Password.Reveal() || strings.Contains(out, "hopInterval") {
				t.Fatal("unstable")
			}
		}
	})
}
