package xray

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
)

// One daemon holds a kernel lease on a dedicated runtime root. Stale artifacts
// are cleaned only after exclusive ownership, without trusting recorded PIDs.
func (e *Engine) generation() (string, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return "", "", unavailable("Xray engine closed")
	}
	if e.root == nil {
		p := e.options.RuntimeDirectory
		if !safePath(p) {
			return "", "", unavailable("unsafe Xray runtime path")
		}
		if err := os.MkdirAll(p, 0700); err != nil {
			return "", "", unavailable("Xray runtime directory unavailable")
		}
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil || resolved != p {
			return "", "", unavailable("unsafe Xray runtime directory")
		}
		if err = secureDirectory(p); err != nil {
			return "", "", unavailable("unsafe Xray runtime permissions")
		}
		root, err := os.OpenRoot(p)
		if err != nil {
			return "", "", unavailable("Xray runtime directory unavailable")
		}
		lease, err := root.OpenFile("owner.lock", os.O_CREATE|os.O_RDWR, 0600)
		if err == nil {
			err = lockLease(lease)
		}
		if err != nil {
			if lease != nil {
				_ = lease.Close()
			}
			_ = root.Close()
			return "", "", unavailable("Xray runtime root already owned or unsafe")
		}
		entries, err := os.ReadDir(p)
		if err == nil {
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), "generation-") && identity.ID(strings.TrimPrefix(entry.Name(), "generation-")).Validate() == nil {
					if err = root.RemoveAll(entry.Name()); err != nil {
						break
					}
				}
			}
		}
		if err != nil {
			_ = lease.Close()
			_ = root.Close()
			return "", "", unavailable("stale Xray artifact cleanup failed")
		}
		e.root = root
		e.lease = lease
	}
	id, err := identity.NewID()
	if err != nil {
		return "", "", err
	}
	name := "generation-" + string(id)
	if e.root.Mkdir(name, 0700) != nil {
		return "", "", unavailable("Xray generation unavailable")
	}
	path := filepath.Join(e.options.RuntimeDirectory, name)
	if secureDirectory(path) != nil {
		_ = e.root.RemoveAll(name)
		return "", "", unavailable("unsafe Xray generation permissions")
	}
	return string(id), path, nil
}
func (e *Engine) removeGeneration(id string) error {
	if identity.ID(id).Validate() != nil {
		return unavailable("invalid Xray generation")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.root == nil {
		return nil
	}
	if e.root.RemoveAll("generation-"+id) != nil {
		return unavailable("Xray artifact cleanup failed")
	}
	return nil
}
