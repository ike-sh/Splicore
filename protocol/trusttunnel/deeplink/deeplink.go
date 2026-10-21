// Package deeplink implements the pinned public TrustTunnel TLV format, v0–2.
// Parsing is separate from admitting a runnable Core profile: subscription and
// optional TLS extensions are represented, never silently made executable.
package deeplink

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/ike-sh/Splicore/protocol/trusttunnel/wire"
)

const MaxURI = 96 << 10
const maxPayload = 64 << 10

var ErrInvalid = errors.New("trusttunnel: invalid bounded deep link")

type Link struct {
	Version                              uint64
	Hostname                             string
	Addresses                            []string
	CustomSNI                            string
	HasIPv6                              bool
	Username, Password                   string
	SkipVerification                     bool
	Certificate                          []byte
	Protocol                             string
	AntiDPI                              bool
	ClientRandomPrefix, Name             string
	DNSUpstreams                         []string
	SubscriptionURL, ClientRandomAuthKey string
}

func (Link) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("TrustTunnelDeepLink{[REDACTED]}")) }
func varint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, ErrInvalid
	}
	n := 1 << uint(b[0]>>6)
	if len(b) < n {
		return 0, 0, ErrInvalid
	}
	v := uint64(b[0] & 63)
	for _, x := range b[1:n] {
		v = v<<8 | uint64(x)
	}
	return v, n, nil
}
func appendVar(b []byte, v uint64) []byte {
	n := 1
	prefix := byte(0)
	switch {
	case v < 64:
	case v < 16384:
		n = 2
		prefix = 64
	case v < 1<<30:
		n = 4
		prefix = 128
	default:
		n = 8
		prefix = 192
	}
	i := len(b)
	b = append(b, make([]byte, n)...)
	for j := n - 1; j >= 0; j-- {
		b[i+j] = byte(v)
		v >>= 8
	}
	b[i] |= prefix
	return b
}
func field(b []byte, tag uint64, v []byte) []byte {
	b = appendVar(b, tag)
	b = appendVar(b, uint64(len(v)))
	return append(b, v...)
}
func parseList(b []byte) ([]string, error) {
	var out []string
	for len(b) > 0 {
		n, k, e := varint(b)
		if e != nil || n > uint64(len(b)-k) || n > 2048 || len(out) >= 16 {
			return nil, ErrInvalid
		}
		v := b[k : k+int(n)]
		if !utf8.Valid(v) || strings.ContainsAny(string(v), "\r\n\x00") {
			return nil, ErrInvalid
		}
		out = append(out, string(v))
		b = b[k+int(n):]
	}
	return out, nil
}
func Parse(raw string) (Link, error) {
	l := Link{HasIPv6: true, Protocol: "http2"}
	if len(raw) > MaxURI || strings.ContainsAny(raw, "\r\n\x00") {
		return l, ErrInvalid
	}
	payload, ok := strings.CutPrefix(raw, "tt://?")
	if !ok {
		payload, ok = strings.CutPrefix(raw, "tt://")
	}
	if !ok || payload == "" {
		return l, ErrInvalid
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(payload)
	if e != nil || len(b) > maxPayload {
		return l, ErrInvalid
	}
	count := 0
	for len(b) > 0 {
		count++
		if count > 256 {
			return Link{}, ErrInvalid
		}
		tag, k, e := varint(b)
		if e != nil {
			return Link{}, e
		}
		b = b[k:]
		n, k, e := varint(b)
		if e != nil || n > uint64(len(b)-k) {
			return Link{}, ErrInvalid
		}
		v := b[k : k+int(n)]
		b = b[k+int(n):]
		switch tag {
		case 0, 9:
			num, k, e := varint(v)
			if e != nil || k != len(v) {
				return Link{}, ErrInvalid
			}
			if tag == 0 {
				l.Version = num
			} else {
				switch num {
				case 1:
					l.Protocol = "http2"
				case 2:
					l.Protocol = "http3"
				default:
					return Link{}, ErrInvalid
				}
			}
		case 4, 7, 10:
			if len(v) != 1 || v[0] > 1 {
				return Link{}, ErrInvalid
			}
			value := v[0] == 1
			switch tag {
			case 4:
				l.HasIPv6 = value
			case 7:
				l.SkipVerification = value
			case 10:
				l.AntiDPI = value
			}
		case 8:
			if len(v) > 48<<10 {
				return Link{}, ErrInvalid
			}
			l.Certificate = append([]byte(nil), v...)
		case 13:
			list, e := parseList(v)
			if e != nil {
				return Link{}, e
			}
			l.DNSUpstreams = list
		case 1, 2, 3, 5, 6, 11, 12, 14, 15:
			if !utf8.Valid(v) || len(v) > 4096 || strings.ContainsAny(string(v), "\x00\r\n") {
				return Link{}, ErrInvalid
			}
			s := string(v)
			switch tag {
			case 1:
				l.Hostname = s
			case 2:
				if len(l.Addresses) >= 16 {
					return Link{}, ErrInvalid
				}
				l.Addresses = append(l.Addresses, s)
			case 3:
				l.CustomSNI = s
			case 5:
				l.Username = s
			case 6:
				l.Password = s
			case 11:
				l.ClientRandomPrefix = s
			case 12:
				l.Name = s
			case 14:
				l.SubscriptionURL = s
			case 15:
				l.ClientRandomAuthKey = s
			}
			// Unknown tags are ignored as required by the public specification.
		}
	}
	if e := l.Validate(); e != nil {
		return Link{}, e
	}
	return l, nil
}
func (l Link) Validate() error {
	if l.Version > 2 || l.Protocol != "http2" && l.Protocol != "http3" || len(l.Addresses) > 16 || len(l.DNSUpstreams) > 16 || len(l.Hostname) > 253 || len(l.CustomSNI) > 253 || len(l.Name) > 128 {
		return ErrInvalid
	}
	if l.SubscriptionURL != "" {
		u, e := url.Parse(l.SubscriptionURL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.Fragment != "" {
			return ErrInvalid
		}
	} else if l.Hostname == "" || len(l.Addresses) == 0 || !wire.Credentials(l.Username, l.Password) {
		return ErrInvalid
	}
	if l.Hostname != "" {
		if _, e := wire.Authority(l.Hostname + ":443"); e != nil {
			return ErrInvalid
		}
	}
	if l.CustomSNI != "" {
		if _, e := wire.Authority(l.CustomSNI + ":443"); e != nil {
			return ErrInvalid
		}
	}
	for _, a := range l.Addresses {
		if _, e := wire.Authority(a); e != nil {
			return ErrInvalid
		}
	}
	if len(l.Certificate) > 48<<10 {
		return ErrInvalid
	}
	if len(l.Certificate) > 0 {
		certs, e := x509.ParseCertificates(l.Certificate)
		if e != nil || len(certs) == 0 || len(certs) > 16 {
			return ErrInvalid
		}
	}
	for _, s := range []string{l.Hostname, l.CustomSNI, l.Username, l.Password, l.Name, l.ClientRandomPrefix, l.ClientRandomAuthKey, l.SubscriptionURL} {
		if !utf8.ValidString(s) || strings.ContainsAny(s, "\x00\r\n") {
			return ErrInvalid
		}
	}
	for _, s := range l.DNSUpstreams {
		if len(s) > 2048 || !utf8.ValidString(s) || strings.ContainsAny(s, "\r\n\x00") {
			return ErrInvalid
		}
	}
	return nil
}

// Encode emits version 1 for static connection fields, compatible with the
// pinned stable client. Subscription links require the documented version 2.
func Encode(l Link) (string, error) {
	l.Version = 1
	if l.SubscriptionURL != "" {
		l.Version = 2
	}
	if e := l.Validate(); e != nil {
		return "", e
	}
	b := field(nil, 0, []byte{byte(l.Version)})
	for _, v := range []struct {
		tag uint64
		s   string
	}{{1, l.Hostname}, {3, l.CustomSNI}, {5, l.Username}, {6, l.Password}, {11, l.ClientRandomPrefix}, {12, l.Name}, {14, l.SubscriptionURL}, {15, l.ClientRandomAuthKey}} {
		if v.s != "" {
			b = field(b, v.tag, []byte(v.s))
		}
	}
	for _, a := range l.Addresses {
		b = field(b, 2, []byte(a))
	}
	if !l.HasIPv6 {
		b = field(b, 4, []byte{0})
	}
	if l.SkipVerification {
		b = field(b, 7, []byte{1})
	}
	if l.AntiDPI {
		b = field(b, 10, []byte{1})
	}
	if len(l.Certificate) > 0 {
		b = field(b, 8, l.Certificate)
	}
	if l.Protocol == "http3" {
		b = field(b, 9, []byte{2})
	}
	if len(l.DNSUpstreams) > 0 {
		var v []byte
		for _, s := range l.DNSUpstreams {
			v = appendVar(v, uint64(len(s)))
			v = append(v, s...)
		}
		b = field(b, 13, v)
	}
	if len(b) > maxPayload {
		return "", ErrInvalid
	}
	return "tt://?" + base64.RawURLEncoding.EncodeToString(b), nil
}
