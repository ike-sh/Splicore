//go:build !with_gvisor

package clientruntime

import (
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-tun"
)

func startOwnedStack(tun.StackOptions) (tun.Stack, error) {
	return nil, identity.Err(identity.NotImplemented, "TUN requires with_gvisor")
}
