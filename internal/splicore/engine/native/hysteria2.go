package native

import (
	"context"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/hysteria2"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-quic/hysteria2"
	"time"
)

type Hysteria2Compiler struct{}
type Hysteria2Handle = quicHandle

func (Hysteria2Compiler) ProtocolID() string { return "hysteria2" }
func (Hysteria2Compiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c Hysteria2Compiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	return newQUICRuntime(ctx, in, s.TLS, func(ctx context.Context, l log.ContextLogger, tls boxtls.ServerConfig, h *quicHandle) (udpService, error) {
		hs, err := hysteria2.NewService[string](hysteria2.ServiceOptions{Context: ctx, Logger: l, TLSConfig: tls, IgnoreClientBandwidth: true, UDPTimeout: 5 * time.Second, Handler: h})
		if err != nil {
			return nil, err
		}
		names, passwords := []string{}, []string{}
		for n, b := range in.Bindings {
			names = append(names, string(b.ID))
			passwords = append(passwords, in.Credentials[n].Payload.(access.PasswordPayload).Password.Reveal())
		}
		hs.UpdateUsers(names, passwords)
		return hs, nil
	})
}
