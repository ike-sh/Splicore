package vless

import (
	"encoding/json"
	"testing"

	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
)

func TestNativeVisionValidation(t *testing.T) {
	s := realitySettings(t)
	s.Flow = Vision
	data, _ := json.Marshal(s)
	if _, e := Decode(data); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"ws", "httpupgrade", "grpc"} {
		s.Stream = &cfg.Config{Kind: kind}
		data, _ = json.Marshal(s)
		if _, e := Decode(data); e == nil {
			t.Fatal("accepted Vision", kind)
		}
	}
	for _, security := range []Security{Plain, TLS, Reality} {
		data, _ := json.Marshal(ClientOptions{Security: security, Flow: Vision, PacketEncoding: "xudp"})
		_, e := DecodeClientOptions(data)
		if (security == Plain) != (e != nil) {
			t.Fatal(security, e)
		}
		c := (Module{Security: security}).Capabilities(ports.CapabilityContext{Engine: "native"})
		if c.Security.Vision != (security != Reality || RealityCompiled) {
			t.Fatal("capability")
		}
	}
	for _, flow := range []Flow{"xtls-rprx-vision-udp443", "xtls-rprx-direct", "unknown", ""} {
		if ValidateFlow(flow) == nil {
			t.Fatal("accepted unsupported flow")
		}
	}
}
