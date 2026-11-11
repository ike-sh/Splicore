package underlay

import (
	"context"
	"net/netip"
)

// HostLookup is a retained Core DNS generation query.
// It selects no proxy route and never retries a failed managed lookup via the OS.
type (
	HostLookup   func(context.Context, string) ([]netip.Addr, error)
	bootstrapKey struct{}
)

func WithBootstrap(ctx context.Context, lookup HostLookup) context.Context {
	return context.WithValue(ctx, bootstrapKey{}, lookup)
}

func BootstrapFrom(ctx context.Context) HostLookup {
	lookup, _ := ctx.Value(bootstrapKey{}).(HostLookup)
	return lookup
}

type targetLookupKey struct{}

func WithTargetLookup(ctx context.Context, lookup HostLookup) context.Context {
	return context.WithValue(ctx, targetLookupKey{}, lookup)
}

func TargetLookupFrom(ctx context.Context) HostLookup {
	lookup, _ := ctx.Value(targetLookupKey{}).(HostLookup)
	return lookup
}
