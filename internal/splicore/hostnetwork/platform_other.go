//go:build !linux && !windows

package hostnetwork

import (
	"context"
	"github.com/sagernet/sing-box/internal/splicore/domain/client"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-tun"
)

type Platform struct{}

func platformCapabilities() Capabilities {
	return Capabilities{TUN: "unsupported", AutoRoute: "unsupported", Driver: "unsupported", Privilege: "unsupported", SystemProxy: "unsupported", LoopProtection: "unsupported"}
}

func NewPlatform() *Platform                    { return &Platform{} }
func (*Platform) CloseOwnedDevice(string) error { return nil }
func (*Platform) Close() error                  { return nil }
func (*Platform) Scope() string                 { return "unsupported-platform" }
func (*Platform) Read(context.Context, Record) (*Record, error) {
	return nil, identity.Err(identity.NotImplemented, "host integration unsupported")
}
func (*Platform) Write(context.Context, Record, *Record) error {
	return identity.Err(identity.NotImplemented, "host integration unsupported")
}
func (*Platform) Device(string) (tun.Tun, error) {
	return nil, identity.Err(identity.NotImplemented, "TUN unsupported")
}
func (*Platform) capturePlan(context.Context, client.TUNSettings, *Plan) error {
	return identity.Err(identity.NotImplemented, "auto-route unsupported")
}
