package vless

import (
	"encoding/json"
	"testing"
)

func TestRealityHandshakeNamesRemainExplicit(t *testing.T) {
	s := realitySettings(t)
	s.Reality.ServerNames = []string{s.Reality.ServerName, "second.synthetic.test"}
	b, _ := json.Marshal(s)
	decoded, e := Decode(b)
	if e != nil || len(decoded.Reality.Names()) != 2 || decoded.Reality.ServerName != s.Reality.ServerName {
		t.Fatal("multiple handshake names lost default", e)
	}
	for _, names := range [][]string{{"second.synthetic.test"}, {s.Reality.ServerName, s.Reality.ServerName}, {s.Reality.ServerName, "127.0.0.1"}, {s.Reality.ServerName, "*.synthetic.test"}, make([]string, 17)} {
		s.Reality.ServerNames = names
		b, _ = json.Marshal(s)
		if _, e = Decode(b); e == nil {
			t.Fatal("invalid handshake names accepted", names)
		}
	}
	s.Reality.ServerNames = nil
	b, _ = json.Marshal(s)
	decoded, e = Decode(b)
	if e != nil || len(decoded.Reality.Names()) != 1 {
		t.Fatal("single-name compatibility", e)
	}
}
