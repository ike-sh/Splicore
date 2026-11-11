package hysteria2_test

import (
	"context"
	"encoding/json"
	cfg "github.com/ike-sh/Splicore/internal/splicore/domain/streamtransport"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	hm "github.com/ike-sh/Splicore/internal/splicore/protocol/hysteria2"
	"testing"
)

func TestObfsRangeClientProfileAndValidation(t *testing.T) {
	in := intent(t)
	var settings hm.Settings
	json.Unmarshal(in.Inbound.Settings.Data, &settings)
	settings.StreamTransport = &cfg.Config{Kind: "hysteria", Hysteria: &cfg.Hysteria{Version: 2, Obfs: &cfg.HysteriaObfs{Type: "gecko", Password: "SyntheticProfileObfs", MinPacketSize: 512, MaxPacketSize: 768}, UDP: &cfg.HysteriaUDP{ServerPortRange: "4433-4444"}, Masquerade: &cfg.Masquerade{Type: "404"}, QUIC: cfg.QUIC{Congestion: "bbr"}}}
	in.Inbound.Settings.Data, _ = json.Marshal(settings)
	p, e := (hm.Module{}).BuildClientProfile(context.Background(), ports.AuthorizedBinding{Inbound: in.Inbound, Binding: in.Bindings[0], Credential: in.Credentials[0]})
	if e != nil {
		t.Fatal(e)
	}
	h := p.Transport.HysteriaSettings()
	if h.Obfs == nil || h.Obfs.Password != "SyntheticProfileObfs" || h.Obfs.MaxPacketSize != 768 || h.UDP == nil || h.UDP.Ports != "4433-4444" || h.UDP.ServerPortRange != "" || h.Masquerade != nil || h.QUIC.Congestion != "" {
		t.Fatal("profile lost or leaked intent")
	}
	in.Inbound.Listeners[0].Endpoint.Port = 4434
	if (hm.Module{}).ValidateInbound(in.Inbound) == nil {
		t.Fatal("listener outside first range port")
	}
}
