package client_test

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"testing"
)

func TestClientIdentityReferencesAndCopy(t *testing.T) {
	id, _ := identity.NewID()
	cid, _ := identity.NewID()
	oid, _ := identity.NewID()
	lid, _ := identity.NewID()
	n := client.RemoteNode{ID: id, Name: "node", Protocol: access.ProtocolKey{Protocol: "snell", WireVersion: "5", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "example.test", Port: 443}, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":5}`)}, Metadata: identity.Metadata{"notes": "synthetic"}}
	state := client.Empty()
	state.Nodes = append(state.Nodes, n)
	state.Outbounds = append(state.Outbounds, client.Outbound{ID: oid, Name: "proxy", Kind: "proxy", NodeID: &id, Engine: "native"})
	state.LocalInbounds = append(state.LocalInbounds, client.LocalInbound{ID: lid, Name: "local", Kind: "socks5", Listen: access.Endpoint{Host: "127.0.0.1", Port: 12345}})
	state.Route.DefaultOutbound = oid
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
	clone := state.Clone()
	clone.Nodes[0].Name = "rename"
	clone.Nodes[0].Metadata["notes"] = "changed"
	clone.Nodes[0].Options.Data[0] = '['
	if state.Nodes[0].Name != "node" || state.Nodes[0].Metadata["notes"] != "synthetic" || state.Nodes[0].Options.Data[0] != '{' {
		t.Fatal("snapshot aliases caller")
	}
	state.Nodes[0].Name = "rename"
	if err := state.Validate(); err != nil || *state.Outbounds[1].NodeID != id {
		t.Fatal("rename broke references", err)
	}
	state.Nodes = nil
	if state.Validate() == nil {
		t.Fatal("dangling node accepted")
	}
}
func TestLocalSOCKSSecurityDefaults(t *testing.T) {
	id, _ := identity.NewID()
	i := client.LocalInbound{ID: id, Name: "local", Listen: access.Endpoint{Port: 12345}}
	i.Defaults()
	if i.Listen.Host != "127.0.0.1" || i.Validate() != nil {
		t.Fatal("loopback default")
	}
	for _, host := range []string{"0.0.0.0", "::", "192.0.2.1", "localhost"} {
		i.Listen.Host = host
		if i.Validate() == nil {
			t.Fatal("unsafe listener", host)
		}
	}
	i.Listen.Host = "::1"
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
}
func FuzzRemoteNode(f *testing.F) {
	f.Add(`{}`)
	f.Add(`{"id":"invalid","endpoint":{"host":"localhost","port":1}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 65536 {
			return
		}
		var n client.RemoteNode
		if jsonstrict.Decode([]byte(raw), &n) == nil {
			_ = n.Validate()
		}
	})
}
func FuzzEndpoint(f *testing.F) {
	f.Add("localhost", uint16(80))
	f.Add("::1", uint16(1))
	f.Add("127.0.0.1", uint16(0))
	f.Fuzz(func(t *testing.T, host string, port uint16) {
		if len(host) > 1024 {
			return
		}
		_ = (access.Endpoint{Host: host, Port: port}).Validate()
		_, _ = access.ParseHost(host)
	})
}
func FuzzOutbound(f *testing.F) {
	f.Add(`{"id":"direct","name":"DIRECT","kind":"direct"}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 65536 {
			return
		}
		var o client.Outbound
		if jsonstrict.Decode([]byte(raw), &o) == nil {
			_ = o.Validate()
		}
	})
}
func FuzzRoute(f *testing.F) {
	f.Add("direct")
	f.Add("missing")
	f.Fuzz(func(t *testing.T, id string) {
		if len(id) > 128 {
			return
		}
		s := client.Empty()
		s.Route.DefaultOutbound = identity.ID(id)
		_ = s.Validate()
		_, _ = json.Marshal(s.Route)
	})
}
