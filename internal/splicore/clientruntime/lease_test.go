package clientruntime

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"testing"
)

func TestReconcileOnlyAffectedAdapterAndCandidateAbort(t *testing.T) {
	id := func() identity.ID { i, _ := identity.NewID(); return i }
	state := client.Empty()
	for range 2 {
		nid, cid, oid := id(), id(), id()
		state.Nodes = append(state.Nodes, client.RemoteNode{ID: nid, Name: "node", Protocol: access.ProtocolKey{Protocol: "snell", WireVersion: "6", FeatureProfile: "base"}, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 1}, CredentialID: cid, Transport: client.Transport{Kind: "tcp"}, Security: client.Security{Kind: "none"}, Options: client.Options{Schema: 1, Data: []byte(`{"version":6}`)}})
		state.Outbounds = append(state.Outbounds, client.Outbound{ID: oid, Name: "out", Kind: "proxy", NodeID: &nid, Engine: "native"})
	}
	f := &retirementFactory{}
	r, _ := registry.NewOutbounds(f)
	m := New()
	defer m.Close(context.Background())
	p, err := m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	state.Route.DefaultOutbound = state.Outbounds[1].ID
	state.Nodes[0].Name = "renamed"
	p, err = m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	if len(f.built) != 2 {
		t.Fatal("route/label change rebuilt adapters")
	}
	state.Nodes[0].Endpoint.Port = 2
	p, err = m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Abort()
	if len(f.built) != 3 {
		t.Fatal("candidate built unrelated adapter")
	}
	select {
	case <-f.built[2].closed:
	default:
		t.Fatal("candidate adapter leaked")
	}
	for _, d := range f.built[:2] {
		select {
		case <-d.closed:
			t.Fatal("abort destroyed committed adapter")
		default:
		}
	}
	p, err = m.Prepare(context.Background(), state, nil, r)
	if err != nil {
		t.Fatal(err)
	}
	p.Activate()
	if len(f.built) != 4 {
		t.Fatal("affected-only rebuild failed")
	}
	select {
	case <-f.built[0].closed:
	default:
		t.Fatal("changed adapter not retired")
	}
	select {
	case <-f.built[1].closed:
		t.Fatal("unrelated adapter retired")
	default:
	}
}
