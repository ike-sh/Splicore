//go:build !linux

package wireguardendpoint

import (
	"errors"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

func TestKernelUnsupportedPlatform(t *testing.T) {
	backend, err := newKernelBackend(nil, E.WireGuard{})
	domain, ok := errors.AsType[*BackendError](err)
	if backend != nil || !ok || domain.Class != UnsupportedPlatform || !fallbackEligible(err) {
		t.Fatalf("unsupported kernel activation: %v", err)
	}
}
