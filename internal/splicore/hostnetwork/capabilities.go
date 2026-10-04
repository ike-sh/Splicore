package hostnetwork

import "github.com/sagernet/sing-tun"

// Passive capability observations contain no host routes, addresses or proxy values.
type Capabilities struct {
	TUN            string `json:"tun"`
	Stack          string `json:"stack"`
	AutoRoute      string `json:"auto_route"`
	Driver         string `json:"driver"`
	Privilege      string `json:"privilege"`
	SystemProxy    string `json:"system_proxy"`
	LoopProtection string `json:"loop_protection"`
}

func PlatformCapabilities() Capabilities {
	c := platformCapabilities()
	if tun.WithGVisor {
		c.Stack = "gvisor"
	} else {
		c.Stack = "not-included"
		c.TUN = "build-unavailable"
	}
	return c
}
