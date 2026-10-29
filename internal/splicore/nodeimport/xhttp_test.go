package nodeimport

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
)

func TestXHTTPCanonicalImportRetainsControls(t *testing.T) {
	b := []byte(`{"schema_version":1,"nodes":[{"node":{"name":"local","protocol":{"protocol":"vless","wire_version":"0","feature_profile":"plain"},"endpoint":{"host":"127.0.0.1","port":8443},"transport":{"kind":"xhttp","path":"/core?tenant=local","host":"core.synthetic.test","headers":{"X-Application":"local"},"xhttp":{"mode":"packet-up","sessionIDPlacement":"cookie","seqPlacement":"query","uplinkDataPlacement":"header","uplinkHTTPMethod":"PUT","xPaddingObfsMode":true,"xPaddingMethod":"tokenish","xPaddingPlacement":"query","scMaxEachPostBytes":"4096-8192","scMinPostsIntervalMs":-1,"xmux":{"maxConnections":1,"cMaxReuseTimes":"10-20"},"downloadSettings":{"endpoint":{"host":"127.0.0.1","port":8444},"transport":{"kind":"xhttp","path":"/core?tenant=local"},"security":"none","tls":{"enabled":false}}}},"security":{"kind":"none","tls":{"enabled":false}},"options":{"schema_version":1,"data":{"security":"none","flow":"none","packet_encoding":"xudp"}},"metadata":{}},"credential":{"kind":"uuid","value":"68f4f564-142b-46b3-8c89-322a37ef1b30"}}]}`)
	r, e := Parse("canonical", b)
	if e != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
		t.Fatalf("canonical import %v %+v", e, r.Issues)
	}
	c := r.Candidates[0].Node.Transport
	if c.XHTTP == nil || c.XHTTP.PacketBytes != (cfg.Range{Min: 4096, Max: 8192}) || c.XHTTP.Download == nil || c.XHTTP.Download.Endpoint != (access.Endpoint{Host: "127.0.0.1", Port: 8444}) {
		t.Fatal("controls lost")
	}
	canonical, e := json.Marshal(Document{Schema: 1, Nodes: r.Candidates})
	if e != nil {
		t.Fatal(e)
	}
	round, e := Parse("canonical", canonical)
	if e != nil || len(round.Candidates) != 1 || !reflect.DeepEqual(c, round.Candidates[0].Node.Transport) {
		t.Fatal("canonical roundtrip lost controls", e)
	}
}

func TestPhase35H3CanonicalImportRetainsIndependentTuning(t *testing.T) {
	b := []byte(`{"schema_version":1,"nodes":[{"node":{"name":"local-h3","protocol":{"protocol":"vless","wire_version":"0","feature_profile":"tls"},"endpoint":{"host":"127.0.0.1","port":8443},"transport":{"kind":"xhttp","h3":{"disableChromeParrot":true,"initStreamReceiveWindow":65536,"maxIncomingStreams":32},"xhttp":{"mode":"packet-up","downloadSettings":{"endpoint":{"host":"::1","port":8444},"transport":{"kind":"xhttp","h3":{"maxIncomingStreams":64}},"security":"tls","tls":{"enabled":true,"server_name":"download.synthetic.test","trust":"system","alpn":["h3"]}}}},"security":{"kind":"tls","tls":{"enabled":true,"server_name":"upload.synthetic.test","trust":"system","alpn":["h3"]}},"options":{"schema_version":1,"data":{"security":"tls","flow":"none","packet_encoding":"xudp"}},"metadata":{}},"credential":{"kind":"uuid","value":"68f4f564-142b-46b3-8c89-322a37ef1b30"}}]}`)
	r, err := Parse("canonical", b)
	if err != nil || len(r.Candidates) != 1 || len(r.Issues) != 0 {
		t.Fatal("H3 import", err, r.Issues)
	}
	tr := r.Candidates[0].Node.Transport
	if tr.H3 == nil || tr.XHTTP.Download.Transport.H3 == nil || tr.H3.MaxIncomingStreams != 32 || tr.XHTTP.Download.Transport.H3.MaxIncomingStreams != 64 {
		t.Fatal("independent tuning collapsed")
	}
	encoded, err := json.Marshal(Document{Schema: 1, Nodes: r.Candidates})
	if err != nil {
		t.Fatal(err)
	}
	round, err := Parse("canonical", encoded)
	if err != nil || len(round.Candidates) != 1 || !reflect.DeepEqual(tr, round.Candidates[0].Node.Transport) {
		t.Fatal("canonical H3 persistence", err)
	}
}
