//go:build with_quic && with_utls

package application_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/application"
	P "github.com/ike-sh/Splicore/internal/splicore/domain/networkpolicy"
	"github.com/ike-sh/Splicore/internal/splicore/networkruntime"
	"github.com/ike-sh/Splicore/internal/splicore/registry"
)

// Exercise shared policies with real classic and SIP023 server/client adapters,
// including health probes and failure/recovery through committed bindings.
func TestPhase19VMessPolicyAcceptance(t *testing.T) {
	ctx := context.Background()
	s, store := setupProtocols(t, filepath.Join(t.TempDir(), "state", "state.db"), nil, registry.NativeCore)
	defer stop(t, s, store)
	enableVMess(t, s)
	var members []P.Action
	var primary application.CreationResult
	for _, method := range []string{"VMess-primary", "VMess-secondary"} {
		created := vmessCreation(t, s)
		if len(members) == 0 {
			primary = created
		}
		candidate := vmessCandidate(t, s, created, 0)
		candidate.Key, candidate.Node.Name = method, method
		_, oid := ssImportedOutbound(t, s, candidate)
		members = append(members, P.Action{Kind: P.Outbound, ID: oid})
	}
	local := freePort(t)
	addLocal(t, s, local, "")
	tcp, udp := echoTarget(t, "127.0.0.1"), expansionUDP(t, "127.0.0.1")
	udp2 := expansionUDP(t, "127.0.0.1")
	group := networkID(t)
	c := P.Config{Route: P.RouteProfile{Final: &P.Action{Kind: P.Group, ID: group}}}
	traffic := func() {
		t.Helper()
		if err := transfer(local, tcp, []byte("VMess policy TCP")); err != nil {
			t.Fatal(err)
		}
		if err := expansionUDPTraffic(local, udp, []byte("VMess policy UDP")); err != nil {
			t.Fatal(err)
		}
		waitIdle(t, s)
	}
	t.Run("Selector", func(t *testing.T) {
		for _, selected := range members {
			c.Groups = []P.PolicyGroup{{ID: group, Name: "VMess selector", Type: "selector", Members: members, Selector: &P.SelectorSettings{Selected: selected}}}
			applyNetwork(t, s, c)
			before := outboundSessions(t, s, selected.ID)
			traffic()
			if outboundSessions(t, s, selected.ID) != before+1 {
				t.Fatal("selector did not use selected VMess node")
			}
		}
	})
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer probe.Close()
	settings := P.Probe{URL: probe.URL, IntervalSeconds: 1, TimeoutSeconds: 2, ExpectedStatus: 204}
	t.Run("URLTest", func(t *testing.T) {
		c.Groups = []P.PolicyGroup{{ID: group, Name: "VMess latency", Type: "url_test", Members: members, URLTest: &P.URLTestSettings{Probe: settings}}}
		applyNetwork(t, s, c)
		g := policyObservation(t, s, group, func(g networkruntime.GroupStatus) bool {
			return g.Available && len(g.Members) == 2 && g.Members[0].Health.State == "healthy" && g.Members[1].Health.State == "healthy"
		})
		if g.Selected != members[0] && g.Selected != members[1] {
			t.Fatal("URL-Test selected a non-member")
		}
		traffic()
	})
	t.Run("FallbackFailureAndRecovery", func(t *testing.T) {
		c.Groups = []P.PolicyGroup{{ID: group, Name: "VMess fallback", Type: "fallback", Members: members, Fallback: &P.FallbackSettings{Probe: settings}}}
		applyNetwork(t, s, c)
		policyObservation(t, s, group, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[0] })
		change := func(enabled bool) {
			t.Helper()
			view, err := s.Inbound(ctx, primary.InboundID)
			if err != nil {
				t.Fatal(err)
			}
			state, err := store.State(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range view.Bindings {
				if b.BindingID == primary.Bindings[0].BindingID {
					_, err = s.SetBinding(ctx, primary.InboundID, application.BindingRequest{BindingID: b.BindingID, Enabled: enabled, ResourceRevision: b.Revision, Revision: state.Revision})
					if err != nil {
						t.Fatal(err)
					}
					return
				}
			}
			t.Fatal("missing primary binding")
		}
		change(false)
		policyObservation(t, s, group, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[1] })
		traffic()
		change(true)
		policyObservation(t, s, group, func(g networkruntime.GroupStatus) bool { return g.Available && g.Selected == members[0] })
		traffic()
	})
	t.Run("LoadBalanceAndUDPAssociationAffinity", func(t *testing.T) {
		c.Groups = []P.PolicyGroup{{ID: group, Name: "VMess balance", Type: "load_balance", Members: members, LoadBalance: &P.LoadBalanceSettings{Algorithm: "round_robin"}}}
		applyNetwork(t, s, c)
		before := []int64{outboundSessions(t, s, members[0].ID), outboundSessions(t, s, members[1].ID)}
		for range 4 {
			if err := transfer(local, tcp, []byte("VMess round robin")); err != nil {
				t.Fatal(err)
			}
		}
		waitIdle(t, s)
		for i, member := range members {
			if outboundSessions(t, s, member.ID) != before[i]+2 {
				t.Fatal("VMess distribution", i)
			}
		}
		pc := heldUDP(t, local, udp)
		defer pc.Close()
		for range 8 {
			checkUDP(t, pc, udp, "VMess affinity first target")
			checkUDP(t, pc, udp2, "VMess affinity second target")
		}
		st, err := s.ClientStatus(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range st.Network.Groups {
			if g.ID == group && g.Selections != 5 {
				t.Fatal("UDP packets advanced load balance", g)
			}
		}
		for _, session := range st.Sessions {
			if session.Kind == "udp_association" && session.OutboundID != members[0].ID {
				t.Fatal("UDP association lost member affinity")
			}
		}
	})
}
