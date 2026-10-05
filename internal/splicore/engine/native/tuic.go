package native

import (
	"context"
	"github.com/gofrs/uuid/v5"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/internal/splicore/domain/access"
	"github.com/sagernet/sing-box/internal/splicore/ports"
	module "github.com/sagernet/sing-box/internal/splicore/protocol/tuic"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-quic/tuic"
	"time"
)

type TUICCompiler struct{}

func (TUICCompiler) ProtocolID() string { return "tuic" }
func (TUICCompiler) Supports(in ports.RuntimeIntent) error {
	_, err := (module.Module{}).BuildRuntime(context.Background(), in)
	return err
}
func (c TUICCompiler) Compile(ctx context.Context, in ports.RuntimeIntent) (ports.PreparedRuntime, error) {
	if err := c.Supports(in); err != nil {
		return nil, err
	}
	s, _ := module.Decode(in.Inbound.Settings.Data)
	return newQUICRuntime(ctx, in, s.TLS, func(ctx context.Context, l log.ContextLogger, tls boxtls.ServerConfig, h *quicHandle) (udpService, error) {
		ts, err := tuic.NewService[string](tuic.ServiceOptions{Context: ctx, Logger: l, TLSConfig: tls, CongestionControl: s.CongestionControl, AuthTimeout: 3 * time.Second, Heartbeat: 10 * time.Second, UDPTimeout: 5 * time.Second, Handler: h})
		if err != nil {
			return nil, err
		}
		names, passwords, uuids := []string{}, []string{}, [][16]byte{}
		for n, b := range in.Bindings {
			p := in.Credentials[n].Payload.(access.UUIDPasswordPayload)
			u, _ := uuid.FromString(p.UUID.Reveal())
			names = append(names, string(b.ID))
			passwords = append(passwords, p.Password.Reveal())
			uuids = append(uuids, [16]byte(u))
		}
		ts.UpdateUsers(names, uuids, passwords)
		return ts, nil
	})
}
