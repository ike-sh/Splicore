package native

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	module "github.com/ike-sh/Splicore/internal/splicore/protocol/trojan"
	"github.com/ike-sh/Splicore/internal/splicore/testkit"
	"github.com/ike-sh/Splicore/internal/splicore/underlay"
)

func TestTrojanTLSCertificateGenerationReplacement(t *testing.T) {
	ctx := underlay.WithFactory(context.Background(), underlay.New())
	in, original := trojanIntent(t)
	first, err := (TrojanCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(context.Background())
	if err = first.(*trojanHandle).Start(ctx); err != nil {
		t.Fatal(err)
	}
	first.(*trojanHandle).Activate()
	tcp, udp := netaddrEndpoint(testfixture.TCP(t).Addr()), trojanUDP(t)
	node, credential := trojanNode(t, in, original, 0)
	oldClient, err := (TrojanOutboundFactory{}).Build(ctx, node, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer oldClient.Close()
	replacement := testkit.TLSForName(t, original.ServerName)
	in.Inbound.Settings.Data, _ = json.Marshal(module.Settings{TLS: replacement})
	second, err := (TrojanCompiler{}).Compile(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(context.Background())
	// Preparing the new certificate cannot mutate the active TLS snapshot.
	trojanTransfer(t, oldClient, tcp, udp)
	if err = first.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = second.(*trojanHandle).Start(ctx); err != nil {
		t.Fatal(err)
	}
	second.(*trojanHandle).Activate()
	if conn, err := oldClient.DialContext(ctx, tcp); err == nil {
		_ = conn.Close()
		t.Fatal("old CA accepted replacement certificate")
	}
	node, credential = trojanNode(t, in, replacement, 0)
	newClient, err := (TrojanOutboundFactory{}).Build(ctx, node, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer newClient.Close()
	trojanTransfer(t, newClient, tcp, udp)
}
