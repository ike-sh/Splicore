package nodeimport

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestMKCPCanonicalImportRetainsTuning(t *testing.T) {
	b := []byte(`{"schema_version":1,"nodes":[{"node":{"name":"local","protocol":{"protocol":"vless","wire_version":"0","feature_profile":"plain"},"endpoint":{"host":"localhost","port":8443},"transport":{"kind":"mkcp","mkcp":{"mtu":576,"tti":10,"uplinkCapacity":0,"downlinkCapacity":1,"cwndMultiplier":3,"maxSendingWindow":8192}},"security":{"kind":"none","tls":{"enabled":false}},"options":{"schema_version":1,"data":{"security":"none","flow":"none","packet_encoding":"xudp"}},"metadata":{}},"credential":{"kind":"uuid","value":"68f4f564-142b-46b3-8c89-322a37ef1b30"}}]}`)
	result, e := Parse("canonical", b)
	if e != nil || len(result.Candidates) != 1 || len(result.Issues) != 0 {
		t.Fatal(e, result.Issues)
	}
	tr := result.Candidates[0].Node.Transport
	if tr.MKCP == nil || tr.MKCP.MTU != 576 || tr.MKCP.CWNDMultiplier != 3 {
		t.Fatal("tuning lost")
	}
	encoded, e := json.Marshal(Document{Schema: 1, Nodes: result.Candidates})
	if e != nil {
		t.Fatal(e)
	}
	round, e := Parse("canonical", encoded)
	if e != nil || len(round.Candidates) != 1 || !reflect.DeepEqual(tr, round.Candidates[0].Node.Transport) {
		t.Fatal("roundtrip lost settings", e)
	}
	invalid := strings.Replace(string(b), `"mtu":576`, `"seed":"legacy","mtu":576`, 1)
	rejected, e := Parse("canonical", []byte(invalid))
	if e == nil && len(rejected.Candidates) > 0 {
		t.Fatal("legacy canonical import accepted")
	}
}
