// Package vless owns canonical VLESS intent; framing and REALITY stay upstream.
package vless

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid/v5"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/jsonstrict"
	"github.com/ike-sh/Splicore/internal/splicore/tlsconfig"
	"strings"
)

type Security string

const (
	Plain   Security = "none"
	TLS     Security = "tls"
	Reality Security = "reality"
)

type Flow string

const (
	NoFlow Flow = "none"
	// Vision remains a recognized input so unsupported requests fail explicitly.
	Vision Flow = "xtls-rprx-vision"
)

// ValidateFlow bounds the supported surface independently of TLS/security.
func ValidateFlow(f Flow) error {
	if f == Vision {
		return identity.Err(identity.NotImplemented, "requested VLESS flow is unsupported")
	}
	if f != NoFlow {
		return invalid()
	}
	return nil
}

type PublicKey string
type ShortID string

func (v *PublicKey) UnmarshalJSON(b []byte) error {
	var value string
	if string(b) == "null" || json.Unmarshal(b, &value) != nil {
		return invalid()
	}
	*v = PublicKey(value)
	return nil
}
func (v *ShortID) UnmarshalJSON(b []byte) error {
	var value string
	if string(b) == "null" || json.Unmarshal(b, &value) != nil {
		return invalid()
	}
	*v = ShortID(value)
	return nil
}

type RealitySettings struct {
	PublicKey  PublicKey       `json:"public_key,omitempty"`
	ShortIDs   []ShortID       `json:"short_ids"`
	ServerName string          `json:"server_name"`
	Target     access.Endpoint `json:"target"`
}
type Settings struct {
	Security       Security            `json:"security"`
	Flow           Flow                `json:"flow"`
	Transport      string              `json:"transport"`
	PacketEncoding string              `json:"packet_encoding"`
	TLS            *tlsconfig.Settings `json:"tls,omitempty"`
	Reality        *RealitySettings    `json:"reality,omitempty"`
	EngineOptions  json.RawMessage     `json:"engine_options,omitempty"`
}

func (Settings) Format(s fmt.State, v rune) { _, _ = s.Write([]byte("VLESSSettings{[REDACTED]}")) }
func invalid() error                        { return identity.Err(identity.Invalid, "invalid VLESS settings or credential") }
func Key(s Security) access.ProtocolKey {
	profile := string(s)
	if s == Plain {
		profile = "plain"
	}
	return access.ProtocolKey{Protocol: "vless", WireVersion: "0", FeatureProfile: profile}
}
func ValidateUUID(v secret.Value) error {
	s := v.Reveal()
	u, err := uuid.FromString(s)
	if err != nil || len(s) != 36 || strings.ToLower(s) != u.String() || u == uuid.Nil {
		return invalid()
	}
	return nil
}
func ParseShortID(s ShortID) ([8]byte, error) {
	var out [8]byte
	if len(s) > 16 || len(s)%2 != 0 {
		return out, invalid()
	}
	if _, err := hex.Decode(out[:], []byte(s)); err != nil {
		return out, invalid()
	}
	return out, nil
}
func ValidatePublicKey(s PublicKey) error {
	b, err := base64.RawURLEncoding.Strict().DecodeString(string(s))
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != string(s) {
		return invalid()
	}
	return nil
}
func DerivePublicKey(p access.PrivateKeyPayload) (PublicKey, error) {
	if p.Validate() != nil {
		return "", invalid()
	}
	b, _ := base64.RawURLEncoding.DecodeString(p.Material.Reveal())
	defer clear(b)
	key, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		return "", invalid()
	}
	return PublicKey(base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())), nil
}
func GenerateServerKey() (access.PrivateKeyPayload, PublicKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return access.PrivateKeyPayload{}, "", identity.Err(identity.Unavailable, "key entropy unavailable")
	}
	b := key.Bytes()
	defer clear(b)
	p := access.PrivateKeyPayload{Algorithm: "x25519", Material: secret.New(base64.RawURLEncoding.EncodeToString(b))}
	pub, err := DerivePublicKey(p)
	return p, pub, err
}
func validateSettings(s Settings, publicRequired bool) error {
	if err := ValidateFlow(s.Flow); err != nil {
		return err
	}
	if s.Transport != "tcp" || s.PacketEncoding != "xudp" {
		return invalid()
	}
	if s.EngineOptions != nil {
		return identity.Err(identity.UnsupportedEngineFeature, "transport masks are outside Splicore runtime")
	}
	switch s.Security {
	case Plain:
		if s.TLS != nil || s.Reality != nil || s.Flow != NoFlow {
			return invalid()
		}
	case TLS:
		if s.TLS == nil || tlsconfig.Validate(*s.TLS) != nil || s.Reality != nil {
			return invalid()
		}
	case Reality:
		if s.TLS != nil || s.Reality == nil {
			return invalid()
		}
		r := s.Reality
		kind, err := access.ParseHost(r.ServerName)
		if err != nil || kind != access.DNS || r.Target.Validate() != nil || len(r.ShortIDs) > 16 {
			return invalid()
		}
		if (publicRequired || r.PublicKey != "") && ValidatePublicKey(r.PublicKey) != nil {
			return invalid()
		}
		seen := map[[8]byte]bool{}
		for _, sid := range r.ShortIDs {
			id, err := ParseShortID(sid)
			if err != nil || seen[id] {
				return invalid()
			}
			seen[id] = true
		}
	default:
		return invalid()
	}
	return nil
}
func decode(b []byte, publicRequired bool) (Settings, error) {
	var s Settings
	if len(b) > 16384 || jsonstrict.Decode(b, &s) != nil {
		return Settings{}, invalid()
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	if raw, ok := fields["engine_options"]; ok && string(raw) == "null" {
		return Settings{}, invalid()
	}
	if err := validateSettings(s, publicRequired); err != nil {
		return Settings{}, err
	}
	if s.Reality != nil {
		if len(s.Reality.ShortIDs) == 0 {
			s.Reality.ShortIDs = []ShortID{""}
		}
		for n, sid := range s.Reality.ShortIDs {
			s.Reality.ShortIDs[n] = ShortID(strings.ToLower(string(sid)))
		}
	}
	return s, nil
}
func Decode(b []byte) (Settings, error) { return decode(b, true) }

type ClientOptions struct {
	Security       Security `json:"security"`
	Flow           Flow     `json:"flow"`
	PacketEncoding string   `json:"packet_encoding"`
}

func DecodeClientOptions(b []byte) (ClientOptions, error) {
	var o ClientOptions
	if len(b) > 16384 || jsonstrict.Decode(b, &o) != nil {
		return o, invalid()
	}
	if err := ValidateFlow(o.Flow); err != nil {
		return o, err
	}
	if o.PacketEncoding != "xudp" || (o.Security != Plain && o.Security != TLS && o.Security != Reality) {
		return o, invalid()
	}
	return o, nil
}
func clientOptions(s Settings) json.RawMessage {
	b, _ := json.Marshal(ClientOptions{Security: s.Security, Flow: s.Flow, PacketEncoding: s.PacketEncoding})
	return b
}
