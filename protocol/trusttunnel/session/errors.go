// Package session owns native TrustTunnel semantics and instance-scoped sessions.
package session

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"golang.org/x/net/http2"
)

type Code string

const (
	DNS             Code = "dns"
	TCP             Code = "tcp_connect"
	QUIC            Code = "quic_connect"
	TLS             Code = "tls_handshake"
	Certificate     Code = "certificate_verification"
	ALPN            Code = "alpn"
	HTTP            Code = "http_protocol"
	Auth            Code = "authentication_required"
	Rejected        Code = "connect_rejected"
	Unavailable     Code = "session_unavailable"
	HealthTimeout   Code = "health_timeout"
	Framing         Code = "udp_framing"
	ICMPUnavailable Code = "icmp_unavailable"
	Config          Code = "unsupported_configuration"
	Closed          Code = "closed"
	Capacity        Code = "capacity"
)

// Error deliberately omits underlying diagnostic text: TLS/HTTP errors can
// contain endpoint or request material. Unwrap retains programmatic identity.
type Error struct {
	Code   Code
	Status int
	cause  error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("trusttunnel: %s (HTTP %d)", e.Code, e.Status)
	}
	return "trusttunnel: " + string(e.Code)
}
func (e *Error) Unwrap() error      { return e.cause }
func failure(c Code, e error) error { return &Error{Code: c, cause: e} }
func IsCode(err error, c Code) bool { var e *Error; return errors.As(err, &e) && e.Code == c }
func classify(c Code, err error) error {
	var cert *tls.CertificateVerificationError
	var host x509.HostnameError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var dns *net.DNSError
	var alert tls.AlertError
	var goAway http2.GoAwayError
	var reset http2.StreamError
	var remote *net.OpError
	if errors.As(err, &cert) || errors.As(err, &host) || errors.As(err, &unknown) || errors.As(err, &invalid) {
		c = Certificate
	} else if errors.As(err, &dns) {
		c = DNS
	} else if errors.As(err, &alert) && alert == 120 {
		c = ALPN
	} else if errors.As(err, &remote) && remote.Op == "remote error" && remote.Err != nil && remote.Err.Error() == "tls: no application protocol" {
		// crypto/tls exposes AlertError for QUIC, but the TCP remote alert is
		// an unexported type inside net.OpError. Match only that exact alert.
		c = ALPN
	} else if errors.As(err, &goAway) && goAway.ErrCode == 0x1f || errors.As(err, &reset) && reset.Code == 0x1f {
		c = Auth
	}
	return failure(classifyH3(c, err), err)
}
func status(code int) error {
	c := Rejected
	if code == 407 {
		c = Auth
	}
	return &Error{Code: c, Status: code}
}
