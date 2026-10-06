package native

import (
	"github.com/ike-sh/Splicore/internal/splicore/engine/testfixture"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"net"
	"testing"
)

func mieruIntent(t *testing.T, transport string) ports.RuntimeIntent {
	return testfixture.MieruIntent(t, transport)
}
func mieruTCPFixture(t *testing.T) net.Listener { return testfixture.TCP(t) }
