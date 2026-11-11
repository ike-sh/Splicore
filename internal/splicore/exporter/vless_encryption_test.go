package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	vl "github.com/ike-sh/Splicore/internal/splicore/protocol/vless"
	"github.com/ike-sh/Splicore/protocol/vless/encryption"
)

func TestVLESSEncryptionExportPreservesIntentAndRejectsLoss(t *testing.T) {
	private, public, err := encryption.Generate("mlkem768", "random", "0rtt", "600s", "100-35-35")
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewID()
	if err != nil {
		t.Fatal(err)
	}
	options, _ := json.Marshal(vl.ClientOptions{Encryption: public, Security: vl.Plain, Flow: vl.NoFlow, PacketEncoding: "xudp"})
	p := clientprofile.Profile{ID: id, Schema: 1, Protocol: vl.Key(vl.Plain), Endpoint: access.Endpoint{Host: "127.0.0.1", Port: 12345}, Credentials: access.UUIDPayload{UUID: secret.New(string(id))}, Transport: clientprofile.Transport{Kind: "tcp"}, UDPPayload: true, Options: access.Settings{Schema: 1, Data: options}}
	ctx := context.Background()
	output, err := (VLESS{Target: ports.Xray}).Export(ctx, p, ports.ExportTarget{Format: ports.Xray, ClientVersion: "26.10.21"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte(public)) || bytes.Contains(output, []byte(private)) || bytes.Contains(output, []byte("decryption")) {
		t.Fatal("encryption export lost intent/disclosed secret")
	}
	for _, target := range []ports.ExportTarget{{Format: ports.URI}, {Format: ports.SingBox, ClientVersion: "1.14.2"}, {Format: ports.Mihomo, ClientVersion: "1.19.32"}, {Format: ports.Xray, ClientVersion: "26.3.27"}, {Format: ports.Xray, ClientVersion: "26.10.31"}} {
		if output, err := (VLESS{Target: target.Format}).Export(ctx, p, target); err == nil || len(output) != 0 {
			t.Fatal("unqualified encrypted export accepted", target.Format)
		}
	}
}
