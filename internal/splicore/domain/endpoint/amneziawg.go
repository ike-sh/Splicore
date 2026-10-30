package endpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrAWGInvalid = errors.New("invalid AmneziaWG 3.1 endpoint configuration")

// AWGRange retains numeric bounds; text exists only at configuration boundaries.
// Zero disables padding and restores upstream defaults for timing fields.
type AWGRange struct{ Min, Max uint32 }

func ParseAWGRange(s string, bits int) (AWGRange, error) {
	if len(s) == 0 || len(s) > 21 || (bits != 16 && bits != 32) {
		return AWGRange{}, ErrAWGInvalid
	}
	for _, c := range s {
		if (c < '0' || c > '9') && c != '-' {
			return AWGRange{}, ErrAWGInvalid
		}
	}
	a, b, found := strings.Cut(s, "-")
	if !found {
		b = a
	}
	lo, e := strconv.ParseUint(a, 10, bits)
	if e != nil {
		return AWGRange{}, ErrAWGInvalid
	}
	hi, e := strconv.ParseUint(b, 10, bits)
	if e != nil || lo > hi {
		return AWGRange{}, ErrAWGInvalid
	}
	return AWGRange{uint32(lo), uint32(hi)}, nil
}

func (r AWGRange) String() string {
	if r.Min == r.Max {
		return strconv.FormatUint(uint64(r.Min), 10)
	}
	return fmt.Sprintf("%d-%d", r.Min, r.Max)
}

func (r AWGRange) Valid(bits int) bool {
	return r.Min <= r.Max && (bits == 32 || bits == 16 && r.Max <= 65535)
}
func (r AWGRange) Zero() bool                   { return r.Min == 0 && r.Max == 0 }
func (r AWGRange) Overlaps(s AWGRange) bool     { return r.Min <= s.Max && s.Min <= r.Max }
func (r AWGRange) MarshalJSON() ([]byte, error) { return json.Marshal(r.String()) }
func (r *AWGRange) UnmarshalJSON(b []byte) error {
	var s string
	if len(b) > 0 && b[0] == '"' {
		if json.Unmarshal(b, &s) != nil {
			return ErrAWGInvalid
		}
	} else {
		s = string(b)
	}
	v, e := ParseAWGRange(s, 32)
	if e == nil {
		*r = v
	}
	return e
}
func (r AWGRange) MarshalYAML() (any, error) { return r.String(), nil }
func (r *AWGRange) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || (n.Tag != "!!str" && n.Tag != "!!int") {
		return ErrAWGInvalid
	}
	v, e := ParseAWGRange(n.Value, 32)
	if e == nil {
		*r = v
	}
	return e
}

type AmneziaWGBackend string

const (
	AWGUserspace AmneziaWGBackend = "userspace"
	AWGKernel    AmneziaWGBackend = "kernel"
	AWGAuto      AmneziaWGBackend = "auto"
)

// AmneziaWG deliberately does not embed WireGuard. Common key/peer validation
// is shared, but no AWG fields can enter a standard WireGuard configuration.
type AmneziaWG struct {
	Protocol               string           `json:"protocol" yaml:"protocol"`
	Version                string           `json:"version" yaml:"version"`
	Backend                AmneziaWGBackend `json:"backend,omitempty" yaml:"backend,omitempty"`
	Tag                    string           `json:"tag" yaml:"tag"`
	Addresses              []string         `json:"addresses" yaml:"addresses"`
	PrivateKey             Secret           `json:"private_key" yaml:"private_key"`
	ListenPort             int              `json:"listen_port" yaml:"listen_port"`
	MTU                    int              `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	Peers                  []WireGuardPeer  `json:"peers" yaml:"peers"`
	Jc                     uint16           `json:"jc,omitempty" yaml:"jc,omitempty"`
	Jmin                   uint16           `json:"jmin,omitempty" yaml:"jmin,omitempty"`
	Jmax                   uint16           `json:"jmax,omitempty" yaml:"jmax,omitempty"`
	S1                     uint16           `json:"s1,omitempty" yaml:"s1,omitempty"`
	S2                     uint16           `json:"s2,omitempty" yaml:"s2,omitempty"`
	S3                     uint16           `json:"s3,omitempty" yaml:"s3,omitempty"`
	S4                     uint16           `json:"s4,omitempty" yaml:"s4,omitempty"`
	H1                     *AWGRange        `json:"h1,omitempty" yaml:"h1,omitempty"`
	H2                     *AWGRange        `json:"h2,omitempty" yaml:"h2,omitempty"`
	H3                     *AWGRange        `json:"h3,omitempty" yaml:"h3,omitempty"`
	H4                     *AWGRange        `json:"h4,omitempty" yaml:"h4,omitempty"`
	I1                     string           `json:"i1,omitempty" yaml:"i1,omitempty"`
	I2                     string           `json:"i2,omitempty" yaml:"i2,omitempty"`
	I3                     string           `json:"i3,omitempty" yaml:"i3,omitempty"`
	I4                     string           `json:"i4,omitempty" yaml:"i4,omitempty"`
	I5                     string           `json:"i5,omitempty" yaml:"i5,omitempty"`
	HeaderProtectionKey    Secret           `json:"header_protection_key,omitempty" yaml:"header_protection_key,omitempty"`
	ContentPaddingAddition AWGRange         `json:"content_padding_addition,omitempty" yaml:"content_padding_addition,omitempty"`
	RekeyAfterTime         AWGRange         `json:"rekey_after_time,omitempty" yaml:"rekey_after_time,omitempty"`
	RekeyTimeout           AWGRange         `json:"rekey_timeout,omitempty" yaml:"rekey_timeout,omitempty"`
	RejectAfterTime        AWGRange         `json:"reject_after_time,omitempty" yaml:"reject_after_time,omitempty"`
	KeepaliveTimeout       AWGRange         `json:"keepalive_timeout,omitempty" yaml:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   AWGRange         `json:"max_handshake_attempts,omitempty" yaml:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool             `json:"random_trailers,omitempty" yaml:"random_trailers,omitempty"`
	DisableCookies         bool             `json:"disable_cookies,omitempty" yaml:"disable_cookies,omitempty"`
}

func (c AmneziaWG) RequestedBackend() AmneziaWGBackend {
	if c.Backend == "" {
		return AWGUserspace
	}
	return c.Backend
}

func (c AmneziaWG) Common() WireGuard {
	return WireGuard{Tag: c.Tag, Addresses: c.Addresses, PrivateKey: c.PrivateKey, ListenPort: c.ListenPort, MTU: c.MTU, Peers: c.Peers}
}
func (c AmneziaWG) InnerMTU() int { return c.Common().InnerMTU() }
func (c AmneziaWG) Clone() AmneziaWG {
	common := c.Common().Clone()
	c.Addresses, c.Peers = common.Addresses, common.Peers
	for _, p := range []**AWGRange{&c.H1, &c.H2, &c.H3, &c.H4} {
		if *p != nil {
			v := **p
			*p = &v
		}
	}
	return c
}

func (c AmneziaWG) Headers() [4]AWGRange {
	h := [4]AWGRange{{1, 1}, {2, 2}, {3, 3}, {4, 4}}
	for i, p := range []*AWGRange{c.H1, c.H2, c.H3, c.H4} {
		if p != nil {
			h[i] = *p
		}
	}
	return h
}
func (c AmneziaWG) Signatures() [5]string { return [5]string{c.I1, c.I2, c.I3, c.I4, c.I5} }
func awgField(name string) error          { return fmt.Errorf("%w: %s", ErrAWGInvalid, name) }
func (c AmneziaWG) Validate() error {
	if c.Protocol != "amneziawg" || c.Version != "3.1" {
		return awgField("protocol/version")
	}
	if b := c.RequestedBackend(); b != AWGUserspace && b != AWGKernel && b != AWGAuto {
		return awgField("backend")
	}
	if c.Common().Validate() != nil {
		return awgField("common keys, addresses or peers")
	}
	if c.RandomTrailers {
		return awgField("RandomTrailers=true is unsupported: unqualified upstream packet classifier")
	}
	if c.Jmin > c.Jmax || c.Jmax > MaxCPSPacket || c.Jc > 64 || uint32(c.Jc)*uint32(c.Jmax) > 65536 {
		return awgField("Jc/Jmin/Jmax work bound")
	}
	sizes := [4]int{148, 92, 64, c.InnerMTU() + 32 + 15}
	for i, s := range []uint16{c.S1, c.S2, c.S3, c.S4} {
		if c.HeaderProtectionKey.Present() && c.HeaderProtectionKey.Reveal() != ([32]byte{}) && s < 12 {
			return awgField(fmt.Sprintf("S%d must be >=12 for HeaderProtectionKey", i+1))
		}
		if int(s)+sizes[i] > 65507 {
			return awgField(fmt.Sprintf("S%d UDP size", i+1))
		}
	}
	h := c.Headers()
	for i, r := range h {
		if !r.Valid(32) {
			return awgField("H range")
		}
		for j := range i {
			if r.Overlaps(h[j]) {
				return awgField("H ranges overlap")
			}
		}
	}
	for _, s := range c.Signatures() {
		if _, err := ParseCPS(s); err != nil {
			return err
		}
	}
	for _, r := range []AWGRange{c.ContentPaddingAddition, c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime, c.KeepaliveTimeout, c.MaxHandshakeAttempts} {
		if !r.Valid(16) {
			return awgField("padding/timing uint16 range")
		}
	}
	// Nonzero timing ranges cannot sample zero: upstream uses duration==0 as
	// the disarmed timer sentinel. An all-zero range restores official defaults.
	for _, r := range []AWGRange{c.RekeyAfterTime, c.RekeyTimeout, c.RejectAfterTime, c.KeepaliveTimeout, c.MaxHandshakeAttempts} {
		if !r.Zero() && r.Min == 0 {
			return awgField("timing range includes zero")
		}
	}
	rekey, reject := c.RekeyAfterTime, c.RejectAfterTime
	if rekey.Zero() {
		rekey = AWGRange{120, 120}
	}
	if reject.Zero() {
		reject = AWGRange{180, 180}
	}
	if rekey.Max >= reject.Min {
		return awgField("RekeyAfterTime must precede RejectAfterTime")
	}
	return nil
}
