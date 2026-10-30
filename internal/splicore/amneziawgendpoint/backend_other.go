//go:build !linux

package amneziawgendpoint

import E "github.com/ike-sh/Splicore/internal/splicore/domain/endpoint"

func newKernelBackend(*Endpoint, E.AmneziaWG) (AmneziaWGBackend, error) {
	return nil, &BackendError{Class: UnsupportedPlatform, Operation: "platform"}
}
