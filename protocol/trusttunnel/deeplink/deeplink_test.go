package deeplink

import (
	"encoding/base64"
	"strings"
	"testing"
)

func basicLink() Link {
	return Link{Hostname: "vpn.example.test", Addresses: []string{"192.0.2.1:443", "[2001:db8::1]:443", "vpn.example.test:8443"}, HasIPv6: true, Username: "test-user", Password: "synthetic:password", Protocol: "http3", Name: "测试 TrustTunnel"}
}
func TestDocumentedTLVRoundtripAndVersions(t *testing.T) {
	l := basicLink()
	uri, e := Encode(l)
	if e != nil {
		t.Fatal(e)
	}
	v, e := Parse(uri)
	if e != nil || v.Version != 1 || v.Hostname != l.Hostname || v.Password != l.Password || len(v.Addresses) != 3 || v.Name != l.Name {
		t.Fatal("roundtrip", e)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(uri, "tt://?"))
	for _, version := range []byte{0, 1, 2} {
		raw[2] = version
		if _, e := Parse("tt://?" + base64.RawURLEncoding.EncodeToString(raw)); e != nil {
			t.Fatal(version, e)
		}
	}
	raw[2] = 3
	if _, e := Parse("tt://?" + base64.RawURLEncoding.EncodeToString(raw)); e == nil {
		t.Fatal("future version")
	}
	raw = raw[3:]
	v, e = Parse("tt://" + base64.RawURLEncoding.EncodeToString(raw))
	if e != nil || v.Version != 0 {
		t.Fatal("legacy", e)
	}
}
func TestLastWinsRepeatedAddressesAndUnknownTags(t *testing.T) {
	u, _ := Encode(basicLink())
	b, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(u, "tt://?"))
	b = field(b, 5, []byte("last-user"))
	b = field(b, 2, []byte("192.0.2.2:443"))
	b = field(b, 999, []byte{255, 0, 1})
	v, e := Parse("tt://?" + base64.RawURLEncoding.EncodeToString(b))
	if e != nil || v.Username != "last-user" || len(v.Addresses) != 4 {
		t.Fatal(e)
	}
}
func TestParserBoundsRequiredFieldsAndSubscription(t *testing.T) {
	for _, raw := range []string{"", "tt://?", "tt://?====", "tt://?AQE_", "tt://?" + strings.Repeat("A", MaxURI), "https://example.test", "tt://?" + base64.RawURLEncoding.EncodeToString([]byte{1, 0xff, 0xff})} {
		if _, e := Parse(raw); e == nil {
			t.Fatal("bad accepted")
		}
	}
	for _, l := range []Link{{Hostname: "host", HasIPv6: true, Protocol: "http2"}, {SubscriptionURL: "http://insecure.test", Protocol: "http2"}, {Version: 3, SubscriptionURL: "https://example.test", Protocol: "http2"}} {
		if l.Validate() == nil {
			t.Fatal("invalid admitted")
		}
	}
	l := Link{SubscriptionURL: "https://test:synthetic@example.test/config", Protocol: "http2", HasIPv6: true}
	u, e := Encode(l)
	if e != nil {
		t.Fatal(e)
	}
	v, e := Parse(u)
	if e != nil || v.SubscriptionURL != l.SubscriptionURL {
		t.Fatal(e)
	}
	l = basicLink()
	l.Certificate = []byte{1, 2, 3}
	if _, e = Encode(l); e == nil {
		t.Fatal("malformed certificate")
	}
}
func FuzzDeepLink(f *testing.F) {
	u, _ := Encode(basicLink())
	f.Add(u)
	f.Add("tt://?AQAB")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > MaxURI+1 {
			return
		}
		l, e := Parse(s)
		if e == nil {
			u, e := Encode(l)
			if e != nil {
				t.Fatal(e)
			}
			got, e := Parse(u)
			if e != nil || got.Hostname != l.Hostname || got.Username != l.Username || got.Password != l.Password || len(got.Addresses) != len(l.Addresses) {
				t.Fatal("roundtrip")
			}
		}
	})
}
