package wireguardendpoint

import (
	"errors"
	"testing"

	E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"
)

func TestKernelNotQualified(t *testing.T) {
	backend, err := newKernelBackend(nil, E.WireGuard{})
	domain, ok := errors.AsType[*BackendError](err)
	if backend != nil || !ok || domain.Class != KernelNotQualified || !fallbackEligible(err) {
		t.Fatalf("unqualified kernel activation: %v", err)
	}
}
