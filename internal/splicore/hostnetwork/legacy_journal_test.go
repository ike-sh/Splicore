package hostnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
)

func TestCoreWritersRejectDesktopResources(t *testing.T) {
	for _, kind := range []string{"proxy", "wininet", "desktop-pac"} {
		b := &fixtureBackend{state: map[string]*Record{}}
		s := &memoryStore{}
		m, err := New(b, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = m.Prepare(context.Background(), []Record{{Kind: kind}}, nil); err == nil || b.writes != 0 || s.saves != 0 {
			t.Fatal("desktop resource entered normal writer", kind, err)
		}
	}
}

func TestRestoredLegacyHistoryPreservedAndCoreRecoveryIndependent(t *testing.T) {
	b := &fixtureBackend{state: map[string]*Record{}}
	s := &memoryStore{}
	m, err := New(b, s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Prepare(context.Background(), []Record{route("198.18.0.0/16")}, nil); err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err = json.Unmarshal(s.data, &wire); err != nil {
		t.Fatal(err)
	}
	legacy := map[string]any{"key": map[string]any{"kind": "proxy", "proxy": map[string]any{"values": map[string]any{"ProxyEnable": map[string]any{"present": true, "type": 4, "number": 1}}}}, "state": "restored"}
	g := wire["generations"].([]any)[0].(map[string]any)
	g["steps"] = append(g["steps"].([]any), legacy)
	s.data, _ = json.Marshal(wire)
	next, err := New(b, s)
	if err != nil {
		t.Fatal(err)
	}
	writes := b.writes
	if err = next.Recover(context.Background()); err != nil || b.writes != writes+1 || next.Status().ActiveGenerations != 0 {
		t.Fatal("Core compensation changed", err)
	}
	if !strings.Contains(string(s.data), `"ProxyEnable"`) {
		t.Fatal("restored historical data deleted")
	}
	legacy["state"] = "active"
	s.data, _ = json.Marshal(wire)
	before := string(s.data)
	writes = b.writes
	saves := s.saves
	_, err = New(b, s)
	var typed *identity.Error
	if !errors.As(err, &typed) || typed.Code != identity.NotImplemented || before != string(s.data) || b.writes != writes || s.saves != saves {
		t.Fatal("unfinished legacy debt altered or guessed", err)
	}
}

func FuzzCoreAndLegacyJournal(f *testing.F) {
	f.Add([]byte(`{"key":{"kind":"proxy","proxy":{"values":{}}},"state":"restored"}`))
	f.Add([]byte(`{"key":{"kind":"route","interface":"synthetic0","prefix":"198.18.0.0/16","table":24000,"protocol":198,"metric":10},"state":"pending"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		var s Step
		if json.Unmarshal(b, &s) != nil {
			return
		}
		out, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var again Step
		if json.Unmarshal(out, &again) != nil {
			t.Fatal("roundtrip")
		}
		if again.legacy != nil && again.State != "restored" {
			t.Fatal("legacy activated")
		}
	})
}
