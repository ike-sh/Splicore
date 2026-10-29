// Package endpoint defines network endpoints independently of proxy protocols.
package endpoint

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"gopkg.in/yaml.v3"
)

var ErrInvalid = errors.New("invalid WireGuard endpoint configuration")

// Secret accepts configuration input but cannot disclose key bytes through
// ordinary formatting or serialization. Reveal is reserved for engine setup.
type Secret struct {
	bytes   [32]byte
	present bool
}

func ParseSecret(value string) (Secret, error) {
	b, err := DecodeKey(value)
	if err != nil {
		return Secret{}, err
	}
	return Secret{bytes: b, present: true}, nil
}
func (s Secret) Reveal() [32]byte             { return s.bytes }
func (s Secret) Present() bool                { return s.present }
func (s Secret) String() string               { return "[REDACTED]" }
func (s Secret) GoString() string             { return s.String() }
func (s Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(s.String())) }
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }
func (s *Secret) UnmarshalJSON(b []byte) error {
	var value string
	if json.Unmarshal(b, &value) != nil {
		return ErrInvalid
	}
	parsed, err := ParseSecret(value)
	if err == nil {
		*s = parsed
	}
	return err
}

func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return ErrInvalid
	}
	parsed, err := ParseSecret(n.Value)
	if err == nil {
		*s = parsed
	}
	return err
}

func DecodeKey(value string) ([32]byte, error) {
	var key [32]byte
	if strings.ContainsAny(value, "\r\n\t ") {
		return key, ErrInvalid
	}
	b, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != len(key) {
		return key, ErrInvalid
	}
	copy(key[:], b)
	return key, nil
}
func EncodeKey(key [32]byte) string { return base64.StdEncoding.EncodeToString(key[:]) }

type WireGuardPeer struct {
	PublicKey                   string   `json:"public_key" yaml:"public_key"`
	PreSharedKey                Secret   `json:"pre_shared_key,omitempty" yaml:"pre_shared_key,omitempty"`
	Endpoint                    string   `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	AllowedIPs                  []string `json:"allowed_ips" yaml:"allowed_ips"`
	PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval,omitempty" yaml:"persistent_keepalive_interval,omitempty"`
}
type WireGuard struct {
	Tag        string          `json:"tag" yaml:"tag"`
	Addresses  []string        `json:"addresses" yaml:"addresses"`
	PrivateKey Secret          `json:"private_key" yaml:"private_key"`
	ListenPort int             `json:"listen_port" yaml:"listen_port"`
	MTU        int             `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	Peers      []WireGuardPeer `json:"peers" yaml:"peers"`
	Reserved   []int           `json:"reserved,omitempty" yaml:"reserved,omitempty"`
}

func (c WireGuard) Clone() WireGuard {
	c.Addresses = append([]string(nil), c.Addresses...)
	c.Reserved = append([]int(nil), c.Reserved...)
	c.Peers = append([]WireGuardPeer(nil), c.Peers...)
	for i := range c.Peers {
		c.Peers[i].AllowedIPs = append([]string(nil), c.Peers[i].AllowedIPs...)
	}
	return c
}

func (c WireGuard) InnerMTU() int {
	if c.MTU == 0 {
		return 1420
	}
	return c.MTU
}

func (c WireGuard) Validate() error {
	if c.Tag == "validate" || !identity.Label(c.Tag, 64) || strings.ContainsAny(c.Tag, "/\\ \t\r\n") || !c.PrivateKey.Present() || c.PrivateKey.Reveal() == ([32]byte{}) || c.ListenPort < 0 || c.ListenPort > 65535 || c.InnerMTU() < 1280 || c.InnerMTU() > 9000 || len(c.Addresses) == 0 || len(c.Addresses) > 16 || len(c.Peers) == 0 || len(c.Peers) > 128 {
		return ErrInvalid
	}
	if c.Reserved != nil && (len(c.Reserved) != 3 || c.Reserved[0] != 0 || c.Reserved[1] != 0 || c.Reserved[2] != 0) {
		return ErrInvalid
	}
	addresses := map[netip.Addr]bool{}
	for _, raw := range c.Addresses {
		p, err := netip.ParsePrefix(raw)
		if err != nil || p.Addr().Is4In6() || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || addresses[p.Addr()] {
			return ErrInvalid
		}
		addresses[p.Addr()] = true
	}
	private := c.PrivateKey.Reveal()
	sk, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return ErrInvalid
	}
	own := base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes())
	keys := map[[32]byte]bool{}
	routes := map[netip.Prefix]bool{}
	for _, p := range c.Peers {
		key, err := DecodeKey(p.PublicKey)
		if err != nil || keys[key] || p.PublicKey == own {
			return ErrInvalid
		}
		keys[key] = true
		pk, err := ecdh.X25519().NewPublicKey(key[:])
		if err != nil {
			return ErrInvalid
		}
		if _, err = sk.ECDH(pk); err != nil {
			return ErrInvalid
		}
		if p.PersistentKeepaliveInterval < 0 || p.PersistentKeepaliveInterval > 65535 || len(p.AllowedIPs) == 0 || len(p.AllowedIPs) > 256 {
			return ErrInvalid
		}
		if p.Endpoint != "" {
			if _, _, err = SplitEndpoint(p.Endpoint); err != nil {
				return ErrInvalid
			}
		}
		for _, raw := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4In6() {
				return ErrInvalid
			}
			prefix = prefix.Masked()
			// Equal routes cannot be assigned to two credentials by declaration order.
			if routes[prefix] {
				return ErrInvalid
			}
			routes[prefix] = true
		}
	}
	return nil
}

func SplitEndpoint(value string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return "", 0, ErrInvalid
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", 0, ErrInvalid
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
			return "", 0, ErrInvalid
		}
	} else {
		if len(host) > 253 || strings.ContainsAny(host, " /\\\r\n\t:%") {
			return "", 0, ErrInvalid
		}
		for label := range strings.SplitSeq(strings.TrimSuffix(host, "."), ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", 0, ErrInvalid
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return "", 0, ErrInvalid
				}
			}
		}
	}
	return host, uint16(n), nil
}
