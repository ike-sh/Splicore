package wireguardendpoint

import E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"

func newKernelBackend(*Endpoint, E.WireGuard) (WireGuardBackend, error) {
	return nil, &BackendError{Class: KernelNotQualified, Operation: "kernel backend excluded from this release"}
}
