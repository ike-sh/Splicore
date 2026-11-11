package nodeimport

import (
	"encoding/json"
	sm "github.com/ike-sh/Splicore/internal/splicore/protocol/snell"
	"testing"
)

func TestSnellV4ImportStrictOptions(t *testing.T) {
	base := map[string]any{"type": "snell", "tag": "test", "server": "localhost", "server_port": 443, "version": 4, "psk": "SyntheticImportPSK12345"}
	for _, options := range []map[string]any{{"reuse": true, "obfs_mode": "http", "obfs_host": "cover.example"}, {"network": "tcp"}} {
		n := map[string]any{}
		for k, v := range base {
			n[k] = v
		}
		for k, v := range options {
			n[k] = v
		}
		b, _ := json.Marshal(n)
		r, e := Parse("sing-box", b)
		if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
			t.Fatal(r, e)
		}
		if _, e := sm.DecodeClient(r.Candidates[0].Node.Options.Data); e != nil {
			t.Fatal(e)
		}
		canonical, _ := json.Marshal(Document{Schema: 1, Nodes: r.Candidates})
		round, e := Parse("canonical", canonical)
		if e != nil || len(round.Candidates) != 1 || string(round.Candidates[0].Node.Options.Data) != string(r.Candidates[0].Node.Options.Data) {
			t.Fatal("canonical options lost", e)
		}
	}
	for _, options := range []map[string]any{{"reuse": nil}, {"udp": nil}, {"obfs_mode": "tls"}, {"obfs_host": "cover.example"}, {"obfs_uri": "/custom"}, {"version": 6, "reuse": true}, {"version": 6, "obfs_mode": "http"}, {"quic": true}, {"udp_port": 1234}, {"obfs-opts": map[string]any{"mode": "http"}}} {
		n := map[string]any{}
		for k, v := range base {
			n[k] = v
		}
		for k, v := range options {
			n[k] = v
		}
		b, _ := json.Marshal(n)
		r, e := Parse("sing-box", b)
		if e == nil && (len(r.Candidates) != 0 || len(r.Issues) != 1) {
			t.Fatal("invalid import accepted", string(b))
		}
	}
}
