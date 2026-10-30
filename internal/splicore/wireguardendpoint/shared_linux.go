//go:build linux

package wireguardendpoint

import "context"

// RunInNamespace shares Phase36's one-shot, m0-safe, restore-verified worker
// with other native endpoint protocols. Callback ownership rules match
// namespaceRun; a poisoned worker must join before rollback is permitted.
func RunInNamespace(ctx context.Context, target int, fn func() error) error {
	return namespaceRun(ctx, target, fn)
}
