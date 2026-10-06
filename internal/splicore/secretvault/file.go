package secretvault

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// InitFile is explicit provisioning, never a fallback for lost keys.
func InitFile(path string) error {
	if runtime.GOOS != "linux" {
		return identity.Err(identity.NotImplemented, "production key provisioning requires Linux permissions")
	}
	if !filepath.IsAbs(path) {
		return identity.Err(identity.Invalid, "key path must be absolute")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return identity.Err(identity.Unavailable, "key directory unavailable")
	}
	if e := checkKeyDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return identity.Err(identity.Unavailable, "key entropy unavailable")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return identity.Err(identity.Unavailable, "key file already exists or cannot be created")
	}
	defer f.Close()
	defer clear(b[:])
	if _, e = f.Write(b[:]); e == nil {
		e = f.Sync()
	}
	if e != nil {
		return identity.Err(identity.Unavailable, "key file write failed")
	}
	return nil
}
func checkKeyDirectory(path string) error {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != filepath.Clean(path) {
		return identity.Err(identity.Invalid, "key directory must not use symlinks")
	}
	i, e := os.Stat(path)
	if e != nil || !i.IsDir() || runtime.GOOS == "linux" && i.Mode().Perm()&0077 != 0 {
		return identity.Err(identity.Invalid, "key directory must be private")
	}
	return keyOwner(i)
}
func LoadFile(path string) (*Vault, error) {
	if !filepath.IsAbs(path) {
		return nil, identity.Err(identity.Invalid, "key path must be absolute")
	}
	if e := checkKeyDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() != 32 || runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0 {
		return nil, identity.Err(identity.Invalid, "key file must be a private regular 32-byte file")
	}
	if e = keyOwner(info); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, identity.Err(identity.Unavailable, "key file unavailable")
	}
	defer f.Close()
	current, e := f.Stat()
	if e != nil || !os.SameFile(info, current) {
		return nil, identity.Err(identity.Invalid, "key file changed while opening")
	}
	if e = keyOwner(current); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, 33))
	defer clear(b)
	if e != nil || len(b) != 32 {
		return nil, identity.Err(identity.Invalid, "invalid key file")
	}
	sum := sha256.Sum256(b)
	return New(hex.EncodeToString(sum[:8]), b)
}
