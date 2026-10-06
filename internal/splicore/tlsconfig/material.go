package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"

	"io"
	"os"
	"path/filepath"
	"runtime"
)

func ReadFileSnapshot(path string, private bool) ([]byte, error) {
	fail := func() ([]byte, error) {
		return nil, identity.Err(identity.Invalid, "TLS material unavailable or unsafe")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return fail()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 65536 {
		return fail()
	}
	if private && runtime.GOOS == "linux" {
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil || !parent.IsDir() || info.Mode().Perm()&0077 != 0 || parent.Mode().Perm()&0077 != 0 {
			return fail()
		}
		if !ownedTLSFile(info) || !ownedTLSFile(parent) {
			return fail()
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return fail()
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return fail()
	}
	b, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(b) > 65536 {
		return fail()
	}
	return b, nil
}
func Snapshot(settings Settings) ([]byte, []byte, error) {
	cert, err := ReadFileSnapshot(settings.CertificateFile, false)
	if err != nil {
		return nil, nil, err
	}
	key, err := ReadFileSnapshot(settings.PrivateKeyFile, true)
	if err != nil {
		return nil, nil, err
	}
	success := false
	defer func() {
		if !success {
			clear(key)
		}
	}()
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, nil, identity.Err(identity.Invalid, "invalid TLS certificate or private key")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, identity.Err(identity.Invalid, "invalid TLS certificate")
	}
	roots, _ := CAPool(settings.CACertificate)
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, identity.Err(identity.Invalid, "invalid TLS certificate chain")
		}
		intermediates.AddCert(c)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: settings.ServerName, Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, nil, identity.Err(identity.Invalid, "TLS certificate identity or trust invalid")
	}
	if leaf.IsCA {
		return nil, nil, identity.Err(identity.Invalid, "TLS server certificate must be a leaf")
	}
	// Include the explicit CA for clients using verified non-leaf CA pinning.
	cert = append(cert, []byte("\n"+settings.CACertificate)...)
	success = true
	return cert, key, nil
}
