//go:build linux && with_gvisor && with_quic && with_utls && splicore_tun_lab

package application_test

import (
	"context"
	"encoding/json"
	"github.com/sagernet/sing-box/internal/splicore/application"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/provider"
	"github.com/sagernet/sing-box/internal/splicore/nodeimport"
	"github.com/sagernet/sing-box/internal/splicore/registry"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPhase14KernelProviderTUN(t *testing.T) {
	requireOwnedTUNLab(t)
	ctx := context.Background()
	root := t.TempDir()
	s, store := setupProtocols(t, filepath.Join(root, "state", "state.db"), nil, func() (*registry.Protocols, *registry.Engines, *registry.Exporters, error) {
		return registry.NativeCore()
	})
	defer stop(t, s, store)
	c := expansionCases(t)[3]
	r, e := registry.NewOutbounds(c.factory)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnableClientRuntime(ctx, r, filepath.Join(root, "host-network")); e != nil {
		t.Fatal(e)
	}
	remote := freePort(t)
	created := expansionCreation(t, s, c, "127.0.0.1", remote)
	creds := []nodeimport.Credential{}
	for i := 0; i < 2; i++ {
		input := payloadInput(expansionCredential(t, store, created, i))
		creds = append(creds, nodeimport.Credential{Kind: input.Kind, Value: input.Value})
	}
	candidate := nodeimport.Candidate{Key: "stable-native-key", Node: client.RemoteNode{Name: "provider", Protocol: c.key, Endpoint: access.Endpoint{Host: "127.0.0.1", Port: remote}, Transport: client.Transport{Kind: "tcp"}, Security: c.security, Options: client.Options{Schema: 1, Data: c.options}}, Credential: creds[0]}
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{candidate}), "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "owned-TUN-provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
	id := p.ProviderID
	if _, e = s.RefreshProvider(ctx, id); e != nil {
		t.Fatal(e)
	}
	status, _ := s.ClientStatus(ctx)
	nid := providerNodes(t, s, id)[0].ID
	oid := identity.ID("")
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == nid {
			oid = o.ID
		}
	}
	clientApply(t, s, application.ClientMutation{Resource: "route", Action: "update", Route: &client.Route{DefaultOutbound: oid}})
	before := tunRouteSnapshot(t)
	tun := client.LocalInbound{Name: "owned-Phase14-TUN", Kind: "tun", TUN: &client.TUNSettings{Interface: "splicore14", Addresses: []string{"198.18.8.1/30", "fd14:1234::1/126"}, MTU: 1500, AutoRoute: true, Stack: "gvisor"}}
	clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "create", LocalInbound: &tun})
	iface, e := net.InterfaceByName("splicore14")
	if e != nil {
		t.Fatal(e)
	}
	var fixturePorts map[string]int
	if json.Unmarshal([]byte(os.Getenv("SPLICORE_TUN_PORTS")), &fixturePorts) != nil {
		t.Fatal("owned fixtures missing")
	}
	destination := net.JoinHostPort("198.19.0.1", strconv.Itoa(fixturePorts["v4tcp"]))
	local := freePort(t)
	addLocal(t, s, local, oid)
	t.Run("refresh-with-held-TUN-and-local-sessions", func(t *testing.T) {
		held := holdTUNApp(t, tunAppRequest{Network: "tcp", Target: destination})
		done := make(chan error, 1)
		go func() {
			for i := 0; i < 10; i++ {
				next := candidate
				next.Node.Name = "renamed"
				next.Credential = creds[(i+1)%2]
				feed.set(feedDocument([]nodeimport.Candidate{next}), "", 0)
				if _, e := s.RefreshProvider(ctx, id); e != nil {
					done <- e
					return
				}
			}
			done <- nil
		}()
		runTUNApp(t, tunAppRequest{Network: "tcp", Target: destination, Size: 4096, Concurrent: 16})
		if e = transfer(local, access.Endpoint{Host: "198.19.0.1", Port: uint16(fixturePorts["v4tcp"])}, []byte("same-daemon-local")); e != nil {
			t.Fatal(e)
		}
		if e = <-done; e != nil {
			t.Fatal(e)
		}
		held("again")
		if current, e := net.InterfaceByName("splicore14"); e != nil || current.Index != iface.Index {
			t.Fatal("refresh rebuilt TUN", e)
		}
		if providerNodes(t, s, id)[0].ID != nid {
			t.Fatal("refresh changed node identity")
		}
		system, e := s.System(ctx)
		if e != nil || system.Health != "healthy" || len(system.ServerRuntimes) != 1 {
			t.Fatal("server runtime affected", e)
		}
	})
	waitIdle(t, s)
	clientApply(t, s, application.ClientMutation{Resource: "runtime", Action: "stop"})
	if tunRouteSnapshot(t) != before {
		t.Fatal("provider/TUN route restore mismatch")
	}
	t.Log("Phase14 Server + Client + actual TUN + fetch + credential rotation 10x PASS; interface reused; retained sessions PASS")
}
