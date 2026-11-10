package hysteria

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	module "github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
)

func masqueradeTLS(t testing.TB) module.Settings {
	return masqueradeTLSForName(t, "hy2.synthetic.test")
}
func masqueradeTLSForName(t testing.TB, name string) module.Settings {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Splicore synthetic CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return module.Settings{ServerName: name, CertificateFile: certPath, PrivateKeyFile: keyPath, CACertificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}
}

func material(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	s := masqueradeTLS(t)
	pair, e := tls.LoadX509KeyPair(s.CertificateFile, s.PrivateKeyFile)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(s.CACertificate))
	return &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{"h3"}}, &tls.Config{RootCAs: pool, ServerName: s.ServerName, NextProtos: []string{"h3"}}
}
