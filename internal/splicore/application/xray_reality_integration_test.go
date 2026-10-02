//go:build splicore_xray_integration && with_utls

package application_test

import (
	"testing"

	v "github.com/sagernet/sing-box/internal/splicore/protocol/vless"
)

func TestXrayPinnedREALITYClientProfileEquivalenceAndSharedAccount(t *testing.T) {
	key, publicKey, err := v.GenerateServerKey()
	if err != nil {
		t.Fatal(err)
	}
	settings := v.Settings{Security: v.Reality, Flow: v.NoFlow, Transport: "tcp", PacketEncoding: "xudp",
		Reality: &v.RealitySettings{PublicKey: publicKey, ServerName: "target.synthetic.test", Target: target(t), ShortIDs: []v.ShortID{"abcd", "", "0123456789abcdef"}}}
	testXrayPinnedTransactionRecoveryAndSharedAccount(t, settings, key.Material.Reveal())
}
