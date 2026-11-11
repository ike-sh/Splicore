package clientruntime

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"strings"
	"testing"
)

func TestHysteriaStatusRedactsObfsSecret(t *testing.T) {
	state := client.Empty()
	state.Nodes = []client.RemoteNode{{Transport: client.Transport{Kind: "hysteria", Hysteria: &cfg.Hysteria{Version: 2, Obfs: &cfg.HysteriaObfs{Type: "salamander", Password: "SyntheticStatusSecret"}}}}}
	m := New()
	view := m.Status(state, nil)
	b, e := json.Marshal(view)
	if e != nil || strings.Contains(string(b), "SyntheticStatusSecret") {
		t.Fatal("obfs exposed", e)
	}
	if state.Nodes[0].Transport.Hysteria.Obfs.Password != "SyntheticStatusSecret" {
		t.Fatal("view mutated stored intent")
	}
}
