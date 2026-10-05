//go:build !with_gvisor

package nativetun

const Included = false

func startBackend(*Runtime) (backend, error) { return nil, ErrUnavailable }
