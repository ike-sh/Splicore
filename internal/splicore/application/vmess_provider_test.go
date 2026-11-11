//go:build with_quic && with_utls

package application_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/application"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/provider"
	"github.com/ike-sh/Splicore/internal/splicore/nodeimport"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPhase19VMessProviderRotation(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	created := vmessCreation(t, s)
	a, b := vmessCandidate(t, s, created, 0), vmessCandidate(t, s, created, 1)
	b.Key = a.Key
	b.Node.Name = a.Node.Name
	feed := &managementFeed{}
	feed.set(feedDocument([]nodeimport.Candidate{a}), "", 0)
	fixture := httptest.NewServer(http.HandlerFunc(feed.serve))
	defer fixture.Close()
	p := managementApply(t, s, application.ManagementRequest{Operation: "provider-upsert", Provider: &provider.Provider{Name: "VMess provider", Kind: "proxy", Format: "canonical", AllowPrivate: true, GenerateOutbounds: true}, Source: &provider.Source{URL: fixture.URL}})
	if _, e := s.RefreshProvider(ctx, p.ProviderID); e != nil {
		t.Fatal(e)
	}
	node := providerNodes(t, s, p.ProviderID)[0]
	status, _ := s.ClientStatus(ctx)
	var oid identity.ID
	for _, o := range status.State.Outbounds {
		if o.NodeID != nil && *o.NodeID == node.ID {
			oid = o.ID
		}
	}
	local := freePort(t)
	addLocal(t, s, local, oid)
	target := echoTarget(t, "127.0.0.1")
	udp := expansionUDP(t, "127.0.0.1")
	var wg sync.WaitGroup
	held, e := socksConn(local, target)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(10 * time.Second))
	checkHeld := func() {
		payload := []byte("retained VMess generation")
		if _, e := held.Write(payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(held, b); e != nil || !bytes.Equal(b, payload) {
			t.Fatal("held session after replacement", e)
		}
	}
	checkHeld()
	failure := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 20 {
			if e := transfer(local, target, []byte("refresh-race")); e != nil {
				failure <- e
				return
			}
			if e := expansionUDPTraffic(local, udp, []byte("rotation-UDP")); e != nil {
				failure <- e
				return
			}
		}
	}()
	for i := range 10 {
		next := a
		if i%2 == 0 {
			next = b
		}
		next.Node.Name = "renamed provider VMess"
		feed.set(feedDocument([]nodeimport.Candidate{next}), "", 0)
		if _, e := s.RefreshProvider(ctx, p.ProviderID); e != nil {
			t.Fatal(e)
		}
		if providerNodes(t, s, p.ProviderID)[0].ID != node.ID {
			t.Fatal("refresh changed immutable ID")
		}
	}
	wg.Wait()
	select {
	case e := <-failure:
		t.Fatal(e)
	default:
	}
	checkHeld()
	held.Close()
	waitIdle(t, s)
	status, _ = s.ClientStatus(ctx)
	generation := status.State.Management.Providers[0].Generation
	feed.set("vmess://invalid", "", 0)
	if _, e := s.RefreshProvider(ctx, p.ProviderID); e == nil {
		t.Fatal("invalid refresh accepted")
	}
	status, _ = s.ClientStatus(ctx)
	if status.State.Management.Providers[0].Generation != generation {
		t.Fatal("failed refresh replaced generation")
	}
	if e := transfer(local, target, []byte("retained committed VMess")); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{a.Credential.Value, b.Credential.Value} {
		doctor, _ := s.Doctor(ctx, "test")
		raw, _ := json.Marshal(doctor)
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("doctor leaked credential")
		}
		raw, _ = json.Marshal(status)
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("status leaked credential")
		}
	}
	preview, e := s.PreviewManagement(ctx, application.ManagementRequest{Operation: "provider-delete", ID: p.ProviderID})
	if e != nil || preview.Applicable {
		t.Fatal("referenced VMess provider deletion", e)
	}
	status, _ = s.ClientStatus(ctx)
	for _, l := range status.State.LocalInbounds {
		if l.Listen.Port == local {
			clientApply(t, s, application.ClientMutation{Resource: "local-inbound", Action: "delete", ID: l.ID})
		}
	}
	managementApply(t, s, application.ManagementRequest{Operation: "provider-delete", ID: p.ProviderID})
	if len(providerNodes(t, s, p.ProviderID)) != 0 {
		t.Fatal("provider deletion retained VMess nodes")
	}
}
