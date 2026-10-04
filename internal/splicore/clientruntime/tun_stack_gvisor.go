//go:build with_gvisor

package clientruntime

import (
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-tun"
)

// Pre-create the upstream endpoint before Start. Upstream Close assumes a
// dispatcher exists; a failed NewEndpoint would otherwise make Close unsafe.
type preparedEndpoint struct {
	tun.GVisorTun
	endpoint stack.LinkEndpoint
	options  stack.NICOptions
}

func (t *preparedEndpoint) NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error) {
	return t.endpoint, t.options, nil
}
func startOwnedStack(options tun.StackOptions) (tun.Stack, error) {
	device, ok := options.Tun.(tun.GVisorTun)
	if !ok {
		return nil, identity.Err(identity.NotImplemented, "gvisor TUN unsupported on this platform")
	}
	ep, nic, err := device.NewEndpoint()
	if err != nil {
		return nil, err
	}
	options.Tun = &preparedEndpoint{device, ep, nic}
	s, err := tun.NewStack("gvisor", options)
	if err != nil {
		ep.Close()
		return nil, err
	}
	if err = s.Start(); err != nil {
		_ = s.Close()
		ep.Close()
		return nil, err
	}
	return s, nil
}
