package proxy

import (
	"context"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ike-sh/Splicore/internal/splicore/clientprofile"
	"github.com/ike-sh/Splicore/internal/splicore/credential"
	"github.com/ike-sh/Splicore/internal/splicore/domain/access"
	"github.com/ike-sh/Splicore/internal/splicore/domain/identity"
	"github.com/ike-sh/Splicore/internal/splicore/domain/secret"
	"github.com/ike-sh/Splicore/internal/splicore/ports"
	"github.com/ike-sh/Splicore/internal/splicore/protocol/creation"
)

// SOCKS5Inbound owns managed, authenticated SOCKS5 server intent.
// Upstream SOCKS5 nodes keep their existing, independent options.
type SOCKS5Inbound struct{}

type socks5ServerOptions struct {
	Auth                 bool `json:"auth"`
	UDP                  bool `json:"udp,omitempty"`
	AllowCleartextRemote bool `json:"allow_cleartext_remote,omitempty"`
}

var socks5Username = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func invalidSOCKS5() error {
	return identity.Err(identity.Invalid, "invalid managed SOCKS5 settings or credentials")
}

func socks5Settings(data json.RawMessage, listener access.Endpoint) (socks5ServerOptions, error) {
	var options socks5ServerOptions
	ip, err := netip.ParseAddr(listener.Host)
	if len(data) > 1024 || creation.Decode(data, &options) != nil || !options.Auth || options.UDP ||
		err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() && !options.AllowCleartextRemote {
		return options, invalidSOCKS5()
	}
	return options, nil
}

func validSOCKS5Password(username string, password secret.Value) bool {
	value := password.Reveal()
	if len(value) < 16 || credential.ValidatePassword(password) != nil || strings.EqualFold(username, value) {
		return false
	}
	var seen [128]bool
	distinct := 0
	for i := range len(value) {
		c := value[i]
		if c < 33 || c > 126 {
			return false
		}
		if !seen[c] {
			seen[c] = true
			distinct++
		}
	}
	return distinct >= 8
}

func (SOCKS5Inbound) Metadata() ports.ProtocolMetadata {
	return ports.ProtocolMetadata{Key: Key("socks5"), Roles: ports.Roles{Inbound: true, Outbound: true},
		ABI: 1, CredentialKinds: []access.CredentialKind{access.UsernamePassword}, Availability: ports.Compiled,
		Provenance: "native RFC 1928 CONNECT and RFC 1929 username/password"}
}

func (SOCKS5Inbound) Capabilities(ports.CapabilityContext) ports.Capabilities {
	return ports.Capabilities{
		Transport: ports.TransportCapabilities{Kinds: []string{"tcp"}, TCP: true, IPv4: true, IPv6: true, DomainEndpoint: true},
		Identity:  ports.IdentityCapabilities{MultiUserNative: true, PerUserStats: true, AttributedPayload: ports.Native, NativeStats: ports.Native},
		Policy:    ports.PolicyCapabilities{Quota: ports.Unsupported, SpeedLimit: ports.Unsupported, MaxSessions: ports.Unsupported},
		Mutation:  ports.MutationCapabilities{Users: ports.Restart, Listener: ports.MutationUnavailable},
		Clients: []ports.ClientCompatibility{
			{Format: ports.Mihomo, Client: "mihomo", Version: "1.19.32"},
			{Format: ports.SingBox, Client: "sing-box", Version: "1.14.2"},
		},
	}
}

func (SOCKS5Inbound) ValidateInbound(in access.Inbound) error {
	if in.Validate() != nil || in.Protocol != Key("socks5") || in.Engine != "native" ||
		len(in.Listeners) != 1 || in.Listeners[0].Transport != "tcp" || len(in.DisplayEndpoints) != 1 {
		return invalidSOCKS5()
	}
	if _, err := socks5Settings(in.Settings.Data, in.Listeners[0].Endpoint); err != nil {
		return err
	}
	if host, err := netip.ParseAddr(in.DisplayEndpoints[0].Endpoint.Host); err == nil && host.IsUnspecified() {
		return invalidSOCKS5()
	}
	return nil
}

func (SOCKS5Inbound) ValidateCredential(c access.Credential) error {
	pair, ok := c.Payload.(access.UsernamePasswordPayload)
	if !ok || c.Validate() != nil || c.State != "active" || !socks5Username.MatchString(pair.Username.Reveal()) ||
		!validSOCKS5Password(pair.Username.Reveal(), pair.Password) {
		return invalidSOCKS5()
	}
	return nil
}

func (m SOCKS5Inbound) BuildRuntime(_ context.Context, in ports.RuntimeIntent) (ports.RuntimeIntent, error) {
	if err := m.ValidateInbound(in.Inbound); err != nil {
		return in, err
	}
	if len(in.Bindings) > 16 || len(in.Bindings) != len(in.Credentials) || len(in.ServerCredentials) != 0 {
		return in, invalidSOCKS5()
	}
	ids, usernames := map[identity.ID]bool{}, map[string]bool{}
	for index, binding := range in.Bindings {
		c := in.Credentials[index]
		if binding.Validate() != nil || !binding.Enabled || ids[binding.ID] || binding.InboundID != in.Inbound.ID ||
			binding.CredentialID != c.ID || c.OwnerAccountID == nil || *c.OwnerAccountID != binding.AccountID || m.ValidateCredential(c) != nil {
			return in, invalidSOCKS5()
		}
		username := c.Payload.(access.UsernamePasswordPayload).Username.Reveal()
		if usernames[username] {
			return in, invalidSOCKS5()
		}
		ids[binding.ID], usernames[username] = true, true
	}
	return in, nil
}

func (m SOCKS5Inbound) BuildClientProfile(ctx context.Context, b ports.AuthorizedBinding) (clientprofile.Profile, error) {
	if _, err := m.BuildRuntime(ctx, ports.RuntimeIntent{Inbound: b.Inbound, Bindings: []access.Binding{b.Binding},
		Credentials: []access.Credential{b.Credential}, ServerCredentials: b.ServerCredentials}); err != nil {
		return clientprofile.Profile{}, err
	}
	options, _ := json.Marshal(Options{Auth: true})
	profile := clientprofile.Profile{ID: b.Binding.ID, Schema: 1, Protocol: Key("socks5"),
		Endpoint: b.Inbound.DisplayEndpoints[0].Endpoint, Credentials: b.Credential.Payload,
		Transport: clientprofile.Transport{Kind: "tcp"}, Options: access.Settings{Schema: 1, Data: options},
		Metadata: identity.Metadata{"display_name": b.Inbound.Name}}
	return profile, profile.Validate()
}

func (SOCKS5Inbound) DecodeCreation(data json.RawMessage) (ports.CreationDraft, error) {
	var w struct {
		Schema   int             `json:"schema"`
		Name     string          `json:"name"`
		Listener access.Endpoint `json:"listener"`
		Display  access.Endpoint `json:"display_endpoint"`
		Settings json.RawMessage `json:"settings"`
		Users    []struct {
			Name      string          `json:"account_name"`
			Enabled   creation.Flag   `json:"enabled,omitempty"`
			Username  string          `json:"username"`
			Password  json.RawMessage `json:"password"`
			ExpiresAt *time.Time      `json:"expires_at,omitempty"`
		} `json:"users"`
	}
	var draft ports.CreationDraft
	if creation.Decode(data, &w) != nil {
		return draft, invalidSOCKS5()
	}
	if w.Listener.Host == "" {
		w.Listener.Host = "127.0.0.1"
	}
	if w.Display == (access.Endpoint{}) {
		w.Display = w.Listener
	}
	options, err := socks5Settings(w.Settings, w.Listener)
	if err != nil || creation.ValidateEnvelope(w.Schema, w.Name, w.Listener, w.Display, "", len(w.Users)) != nil {
		return draft, invalidSOCKS5()
	}
	if host, err := netip.ParseAddr(w.Display.Host); err == nil && host.IsUnspecified() {
		return draft, invalidSOCKS5()
	}
	settings, _ := json.Marshal(options)
	draft = ports.CreationDraft{Name: w.Name, Protocol: Key("socks5"), Transport: "tcp",
		Listener: w.Listener, Display: w.Display, Settings: settings}
	names, usernames := map[string]bool{}, map[string]bool{}
	enabled := false
	for _, user := range w.Users {
		password, err := creation.RawField(user.Password)
		value := secret.New(password)
		if err != nil || creation.ValidateUser(user.Name, nil, "", names) != nil ||
			user.ExpiresAt != nil && (user.ExpiresAt.IsZero() || user.ExpiresAt.Location() != time.UTC) ||
			!socks5Username.MatchString(user.Username) || usernames[user.Username] ||
			(!value.Empty() && !validSOCKS5Password(user.Username, value)) {
			return draft, invalidSOCKS5()
		}
		usernames[user.Username] = true
		bindingEnabled := creation.Enabled(user.Enabled)
		enabled = enabled || bindingEnabled && (user.ExpiresAt == nil || time.Now().Before(*user.ExpiresAt))
		draft.Users = append(draft.Users, ports.CreationUser{Name: user.Name, Enabled: bindingEnabled, AccountEnabled: true,
			Payload: access.UsernamePasswordPayload{Username: secret.New(user.Username), Password: value}, ExpiresAt: user.ExpiresAt})
	}
	if !enabled {
		return draft, invalidSOCKS5()
	}
	return draft, nil
}

func (SOCKS5Inbound) GenerateCreationCredential(payload access.Payload) (access.Payload, error) {
	pair, ok := payload.(access.UsernamePasswordPayload)
	if !ok || !socks5Username.MatchString(pair.Username.Reveal()) {
		return nil, invalidSOCKS5()
	}
	if pair.Password.Empty() {
		password, err := credential.GeneratePassword()
		if err != nil {
			return nil, err
		}
		pair.Password = password
	}
	if !validSOCKS5Password(pair.Username.Reveal(), pair.Password) {
		return nil, invalidSOCKS5()
	}
	return pair, nil
}
