// Package access owns proxy identities and authorizations, independent of engines.
package access

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/internal/splicore/domain/identity"
	"github.com/sagernet/sing-box/internal/splicore/domain/secret"
)

type Status string

const (
	Active    Status = "active"
	Suspended Status = "suspended"
	Closed    Status = "closed"
)

type Account struct {
	ID        identity.ID       `json:"id"`
	Name      string            `json:"name"`
	Status    Status            `json:"status"`
	Enabled   bool              `json:"enabled"`
	ExpiresAt *time.Time        `json:"expires_at,omitempty"`
	Metadata  identity.Metadata `json:"metadata"`
	identity.Stamp
}

func (a Account) Validate() error {
	if err := a.ID.Validate(); err != nil {
		return err
	}
	if !identity.Label(a.Name, 128) || (a.Status != Active && a.Status != Suspended && a.Status != Closed) {
		return identity.Err(identity.Invalid, "invalid account name or status")
	}
	if a.ExpiresAt != nil && (a.ExpiresAt.IsZero() || a.ExpiresAt.Location() != time.UTC) {
		return identity.Err(identity.Invalid, "expiry must be UTC")
	}
	if err := a.Metadata.Validate(); err != nil {
		return err
	}
	return a.Stamp.Validate()
}

type Binding struct {
	ID               identity.ID  `json:"id"`
	AccountID        identity.ID  `json:"account_id"`
	InboundID        identity.ID  `json:"inbound_id"`
	CredentialID     identity.ID  `json:"credential_id"`
	Enabled          bool         `json:"enabled"`
	PolicyOverrideID *identity.ID `json:"policy_override_id,omitempty"`
	identity.Stamp
}

func (b Binding) Validate() error {
	for _, id := range []identity.ID{b.ID, b.AccountID, b.InboundID, b.CredentialID} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if b.PolicyOverrideID != nil {
		if err := b.PolicyOverrideID.Validate(); err != nil {
			return err
		}
	}
	return b.Stamp.Validate()
}

type CredentialKind string

const (
	PSK              CredentialKind = "psk"
	UUID             CredentialKind = "uuid"
	UUIDPassword     CredentialKind = "uuid_password"
	UsernamePassword CredentialKind = "username_password"
	Password         CredentialKind = "password"
	PrivateKey       CredentialKind = "private_key"
)

// Payload is a tagged closed set of typed secret values, not protocol columns.
type Payload interface {
	Kind() CredentialKind
	Validate() error
	credentialPayload()
}

func ValidatePayload(p Payload) error {
	switch v := p.(type) {
	case PSKPayload:
		return v.Validate()
	case UUIDPayload:
		return v.Validate()
	case UUIDPasswordPayload:
		return v.Validate()
	case UsernamePasswordPayload:
		return v.Validate()
	case PasswordPayload:
		return v.Validate()
	case PrivateKeyPayload:
		return v.Validate()
	default:
		return identity.Err(identity.Invalid, "unsupported or nil credential payload")
	}
}

type (
	PSKPayload          struct{ Key secret.Value }
	UUIDPayload         struct{ UUID secret.Value }
	UUIDPasswordPayload struct {
		UUID     secret.Value
		Password secret.Value
	}
)

type UsernamePasswordPayload struct {
	Username secret.Value
	Password secret.Value
}

// PasswordPayload has no fabricated protocol username.
type PasswordPayload struct{ Password secret.Value }

func (PasswordPayload) Kind() CredentialKind { return Password }
func (PasswordPayload) credentialPayload()   {}
func (p PasswordPayload) Validate() error {
	if !validSecret(p.Password) {
		return identity.Err(identity.Invalid, "invalid credential material")
	}
	return nil
}

func (PSKPayload) Kind() CredentialKind              { return PSK }
func (UUIDPayload) Kind() CredentialKind             { return UUID }
func (UUIDPasswordPayload) Kind() CredentialKind     { return UUIDPassword }
func (UsernamePasswordPayload) Kind() CredentialKind { return UsernamePassword }
func (PSKPayload) credentialPayload()                {}
func (UUIDPayload) credentialPayload()               {}
func (UUIDPasswordPayload) credentialPayload()       {}
func (UsernamePasswordPayload) credentialPayload()   {}
func validSecret(v secret.Value) bool                { return !v.Empty() && len(v.Reveal()) <= 4096 }

func validUUID(v secret.Value) bool {
	s := v.Reveal()
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (p PSKPayload) Validate() error {
	if !validSecret(p.Key) {
		return identity.Err(identity.Invalid, "invalid credential material")
	}
	return nil
}

func (p UUIDPayload) Validate() error {
	if !validUUID(p.UUID) {
		return identity.Err(identity.Invalid, "invalid credential material")
	}
	return nil
}

func (p UUIDPasswordPayload) Validate() error {
	if !validUUID(p.UUID) || !validSecret(p.Password) {
		return identity.Err(identity.Invalid, "invalid credential material")
	}
	return nil
}

func (p UsernamePasswordPayload) Validate() error {
	if !validSecret(p.Username) || !validSecret(p.Password) {
		return identity.Err(identity.Invalid, "invalid credential material")
	}
	return nil
}

type Credential struct {
	ID             identity.ID    `json:"id"`
	OwnerAccountID *identity.ID   `json:"owner_account_id,omitempty"`
	OwnerInboundID *identity.ID   `json:"owner_inbound_id,omitempty"`
	Kind           CredentialKind `json:"kind"`
	Schema         int            `json:"schema_version"`
	State          string         `json:"state"`
	Payload        Payload        `json:"-"`
	identity.Stamp
}

func (c Credential) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("Credential{" + secret.Redacted + "}"))
}

func (c Credential) Validate() error {
	if err := c.ID.Validate(); err != nil {
		return err
	}
	if (c.OwnerAccountID == nil) == (c.OwnerInboundID == nil) {
		return identity.Err(identity.Invalid, "credential needs exactly one owner")
	}
	for _, id := range []*identity.ID{c.OwnerAccountID, c.OwnerInboundID} {
		if id != nil {
			if err := id.Validate(); err != nil {
				return err
			}
		}
	}
	if c.Schema != 1 || c.State != "active" && c.State != "revoked" {
		return identity.Err(identity.Invalid, "invalid credential schema or state")
	}
	if err := ValidatePayload(c.Payload); err != nil {
		return err
	}
	if c.Kind != c.Payload.Kind() {
		return identity.Err(identity.Invalid, "credential kind mismatch")
	}
	return c.Stamp.Validate()
}

type HostKind string

const (
	IPv4 HostKind = "ipv4"
	IPv6 HostKind = "ipv6"
	DNS  HostKind = "dns"
)

type Endpoint struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

func ParseHost(host string) (HostKind, error) {
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		if ip.Is4() {
			return IPv4, nil
		}
		return IPv6, nil
	}
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\\t\r\n:@[]?#%") {
		return "", identity.Err(identity.Invalid, "invalid endpoint host")
	}
	// IPv6 contains ':' and is checked separately to prevent accepting host:port.
	numeric := true
	for _, c := range host {
		if c != '.' && (c < '0' || c > '9') {
			numeric = false
		}
		if c > 127 || c < 33 {
			return "", identity.Err(identity.Invalid, "invalid endpoint host")
		}
	}
	if numeric {
		return "", identity.Err(identity.Invalid, "invalid numeric IP address")
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", identity.Err(identity.Invalid, "invalid DNS hostname")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", identity.Err(identity.Invalid, "invalid DNS hostname")
			}
		}
	}
	return DNS, nil
}

func (e Endpoint) Validate() error {
	if e.Port == 0 {
		return identity.Err(identity.Invalid, "endpoint port must be nonzero")
	}
	// Parse IP before DNS validation so raw IPv6 is accepted, zones are not.
	if ip, err := netip.ParseAddr(e.Host); err == nil && ip.Zone() == "" {
		return nil
	}
	_, err := ParseHost(e.Host)
	return err
}

type ProtocolKey struct {
	Protocol       string `json:"protocol"`
	WireVersion    string `json:"wire_version"`
	FeatureProfile string `json:"feature_profile"`
}

func (k ProtocolKey) String() string {
	return k.Protocol + "/" + k.WireVersion + "/" + k.FeatureProfile
}

func (k ProtocolKey) Validate() error {
	for _, v := range []string{k.Protocol, k.WireVersion, k.FeatureProfile} {
		if !identity.Label(v, 64) || strings.ContainsAny(v, "/ :") {
			return identity.Err(identity.Invalid, "invalid protocol identity")
		}
	}
	return nil
}

// Settings is a bounded versioned protocol extension. Only an adapter validates its schema.
type Settings struct {
	Schema int             `json:"schema_version"`
	Data   json.RawMessage `json:"-"`
}

func (s Settings) Format(f fmt.State, verb rune) {
	_, _ = f.Write([]byte("Settings{" + secret.Redacted + "}"))
}

func (s Settings) MarshalJSON() ([]byte, error) {
	return []byte(`{"schema_version":1,"data":"[REDACTED]"}`), nil
}

func (s Settings) Validate() error {
	if s.Schema != 1 || len(s.Data) > 16384 || !json.Valid(s.Data) {
		return identity.Err(identity.Invalid, "invalid protocol settings")
	}
	return nil
}

type Listener struct {
	ID        identity.ID `json:"id"`
	Transport string      `json:"transport"`
	Endpoint  Endpoint    `json:"endpoint"`
}
type DisplayEndpoint struct {
	ID       identity.ID `json:"id"`
	Endpoint Endpoint    `json:"endpoint"`
	Priority int         `json:"priority"`
}
type Inbound struct {
	ID               identity.ID       `json:"id"`
	NodeID           identity.ID       `json:"node_id"`
	Name             string            `json:"name"`
	Protocol         ProtocolKey       `json:"protocol"`
	Engine           string            `json:"engine"`
	Listeners        []Listener        `json:"listeners"`
	DisplayEndpoints []DisplayEndpoint `json:"display_endpoints"`
	Enabled          bool              `json:"enabled"`
	Tags             []string          `json:"tags"`
	Settings         Settings          `json:"settings"`
	identity.Stamp
}

func (i Inbound) Validate() error {
	for _, id := range []identity.ID{i.ID, i.NodeID} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if !identity.Label(i.Name, 128) || !identity.Label(i.Engine, 64) || len(i.Listeners) == 0 || len(i.Listeners) > 16 || len(i.DisplayEndpoints) == 0 || len(i.DisplayEndpoints) > 16 || len(i.Tags) > 32 {
		return identity.Err(identity.Invalid, "invalid inbound dimensions")
	}
	if err := i.Protocol.Validate(); err != nil {
		return err
	}
	seen := make(map[identity.ID]bool)
	for _, l := range i.Listeners {
		if err := l.ID.Validate(); err != nil {
			return err
		}
		if seen[l.ID] || l.Transport != "tcp" && l.Transport != "udp" {
			return identity.Err(identity.Invalid, "invalid listener")
		}
		seen[l.ID] = true
		if err := l.Endpoint.Validate(); err != nil {
			return err
		}
		if _, err := netip.ParseAddr(l.Endpoint.Host); err != nil {
			return identity.Err(identity.Invalid, "listener must bind an IP address")
		}
	}
	for _, e := range i.DisplayEndpoints {
		if err := e.ID.Validate(); err != nil {
			return err
		}
		if seen[e.ID] || e.Priority < 0 {
			return identity.Err(identity.Invalid, "invalid display endpoint")
		}
		seen[e.ID] = true
		if err := e.Endpoint.Validate(); err != nil {
			return err
		}
	}
	tags := make(map[string]bool)
	for _, t := range i.Tags {
		if !identity.Label(t, 64) || tags[t] {
			return identity.Err(identity.Invalid, "invalid tags")
		}
		tags[t] = true
	}
	if err := i.Settings.Validate(); err != nil {
		return err
	}
	return i.Stamp.Validate()
}
