package clientruntime

import (
	"encoding/json"
	"github.com/ike-sh/Splicore/internal/splicore/domain/client"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/finalmask"
	"strings"
	"testing"
)

func TestFinalMaskStatusRedactsSettings(t *testing.T) {
	state := client.Empty()
	state.Nodes = []client.RemoteNode{{Transport: client.Transport{Kind: "tcp", FinalMask: &cfg.Config{TCP: []cfg.Mask{{Type: "sudoku", Settings: json.RawMessage(`{"password":"synthetic-mask-secret"}`)}}}}}}
	m := New()
	view := m.Status(state, nil)
	b, e := json.Marshal(view)
	if e != nil || strings.Contains(string(b), "synthetic-mask-secret") {
		t.Fatal("mask settings exposed", e)
	}
	if string(state.Nodes[0].Transport.FinalMask.TCP[0].Settings) != `{"password":"synthetic-mask-secret"}` {
		t.Fatal("diagnostic mutated intent")
	}
}
