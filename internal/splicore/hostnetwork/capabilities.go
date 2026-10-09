package hostnetwork

import "github.com/ike-sh/Splicore/internal/splicore/nativetun"

// Passive capability observations contain no host routes, addresses or private values.
type Capabilities struct {
	TUN            string `json:"tun"`
	Stack          string `json:"stack"`
	AutoRoute      string `json:"auto_route"`
	Driver         string `json:"driver"`
	Privilege      string `json:"privilege"`
	LoopProtection string `json:"loop_protection"`
}

func PlatformCapabilities() Capabilities {
	c := platformCapabilities()
	if nativetun.Included {
		c.Stack = "gvisor"
	} else {
		c.Stack = "not-included"
		c.TUN = "build-unavailable"
	}
	return c
}
