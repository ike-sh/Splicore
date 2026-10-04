//go:build !linux

package underlay

import (
	"context"
	"syscall"
)

type unavailableBackend struct{}

func platformBackend() Backend { return unavailableBackend{} }
func (unavailableBackend) Capabilities() Capabilities {
	return Capabilities{Strategy: "activation-unqualified"}
}
func (unavailableBackend) Protect(context.Context, Scope, string, string, syscall.RawConn) error {
	return unsafe("platform protection unqualified")
}
func (unavailableBackend) Reconcile(context.Context, []Endpoint) error {
	return unsafe("platform protection unqualified")
}
func (unavailableBackend) Verify(context.Context) error {
	return unsafe("platform protection unqualified")
}
