package clientconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
)

// TLS snapshots the committed verification inputs. Library configurations may
// mutate their clone without changing a node's configuration or another flow.
func TLS(settings access.ClientTLS, endpoint string) (*tls.Config, error) {
	name := settings.ServerName
	if name == "" {
		name = endpoint
	}
	c := &tls.Config{ServerName: name, NextProtos: slices.Clone(settings.ALPN), MinVersion: tls.VersionTLS12}
	if settings.CACertificate != "" {
		c.RootCAs = x509.NewCertPool()
		if !c.RootCAs.AppendCertsFromPEM([]byte(settings.CACertificate)) {
			return nil, errors.New("invalid client CA certificate")
		}
	}
	return c, nil
}
