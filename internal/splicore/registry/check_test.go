package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/secretvault"
)

func TestCheckCreationValidatesTLSResources(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	// Use the production platform-specific private directory provisioning.
	if err := secretvault.InitFile(filepath.Join(dir, "fixture.key")); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runtime test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"runtime.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{
		"schema": 1, "name": "offline-tls", "listener": map[string]any{"host": "127.0.0.1", "port": 31337}, "display_endpoint": map[string]any{"host": "127.0.0.1", "port": 31337},
		"settings": map[string]any{"security": "tls", "flow": "none", "transport": "tcp", "packet_encoding": "xudp", "tls": map[string]any{"server_name": "runtime.test", "certificate_file": certPath, "private_key_file": keyPath, "ca_certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}},
		"users":    []any{map[string]any{"account_name": "offline-user", "uuid": "c60224f4-8ee9-4f3e-a605-5af746b89fe8"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	protocols, engines, _, err := NativeCore()
	if err != nil {
		t.Fatal(err)
	}
	if err := protocols.CheckCreation(engines, "vless", document); err != nil {
		t.Fatal("valid TLS resources rejected:", err)
	}
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if err := protocols.CheckCreation(engines, "vless", document); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid private key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protocols.CheckCreation(engines, "vless", document); err == nil {
		t.Fatal("invalid private key accepted")
	}
}
